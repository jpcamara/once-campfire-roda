require "roda"
require "rack/method_override"
require "rack/files"
require "securerandom"
require "bcrypt"
require "uri"

module Campfire
  ROOT = File.expand_path("../..", __dir__)

  # Process-wide state shared by requests: the database, secrets and caches.
  class Runtime
    attr_reader :db, :repo, :secrets, :fragment_cache, :vapid_public_key, :app_version, :git_revision

    def initialize
      @db = DB.new
      @repo = Repo.new(@db)
      @secrets = RailsCompat::Secrets.new(ENV.fetch("SECRET_KEY_BASE"))
      @fragment_cache = FragmentCache.new(ENV.fetch("FRAGMENT_CACHE_SIZE", 5_000).to_i)
      @vapid_public_key = ENV["VAPID_PUBLIC_KEY"]
      @app_version = ENV["APP_VERSION"].to_s.empty? ? (ENV["GIT_REVISION"].to_s.empty? ? "0" : ENV["GIT_REVISION"]) : ENV["APP_VERSION"]
      @git_revision = ENV["GIT_REVISION"]
      @avatar_tokens = {}
    end

    def account
      @repo.account
    end

    # Current.account&.logo&.attached?: there's no account before first run.
    def account_logo_attached?
      (account = self.account) && !@repo.attachment_blob("Account", account.id, "logo").nil?
    end

    def avatar_token(user_id)
      return @secrets.signed_id(user_id, "user/avatar").freeze if Campfire.rust_caching_only?
      @avatar_tokens[user_id] ||= @secrets.signed_id(user_id, "user/avatar").freeze
    end

    def all_emoji?(text)
      text.match?(/\A(\p{Emoji_Presentation}|\p{Extended_Pictographic}|️)+\z/u)
    end

    def blob_path(blob, disposition: nil)
      Storage.blob_path(self, blob, disposition: disposition)
    end
  end

  module Tokens
    BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".chars.freeze

    BASE36 = [ *"0".."9", *"a".."z" ].freeze

    # ActiveSupport's SecureRandom.base58, as has_secure_token uses it.
    def self.base58(length)
      Array.new(length) { BASE58[SecureRandom.random_number(58)] }.join
    end

    # SecureRandom.base36, as Active Storage generates blob keys.
    def self.base36(length)
      Array.new(length) { BASE36[SecureRandom.random_number(36)] }.join
    end
  end

  # A bounded per-process cache for rendered fragments, evicting the oldest entries first.
  class FragmentCache
    def initialize(limit)
      @limit = limit
      @entries = {}
    end

    def key?(key)
      @entries.key?(key)
    end

    def fetch(key)
      if (value = @entries.delete(key))
        @entries[key] = value
      else
        value = yield
        @entries[key] = value
        @entries.delete(@entries.first[0]) while @entries.size > @limit
        value
      end
    end
  end

  # Roda's response finished the way Rails finishes ActionController responses, as the handlers
  # below expect: a handler's value is the whole body (a String, or a body object such as
  # FragmentBody), the status is 200 unless set, an unset Content-Type is text/html, 204 and 304
  # carry no body or content headers, and Content-Length is counted for string bodies.
  module Responses
    module RequestMethods
      # Every route ends here: the handler's value, or nil when nothing matched.
      def block_result(result) = scope.respond(result)
    end

    module ResponseMethods
      attr_accessor :result_body

      def finish
        status = @status || 200
        headers = @headers
        body = result_body || []
        headers["content-type"] ||= "text/html;charset=utf-8"
        if status == 204 || status == 304 || status.between?(100, 199)
          headers.delete("content-length")
          headers.delete("content-type")
          body = []
        end
        headers["content-length"] ||= body.sum(&:bytesize).to_s if body.is_a?(Array)
        [ status, headers, body ]
      end
    end
  end

  class App < Roda
    PERMANENT_YEARS = 20
    SESSION_REFRESH = 3600

    plugin :all_verbs
    plugin :head
    plugin :cookies
    plugin Responses
    # Forms send PATCH, PUT and DELETE as POST with _method.
    use Rack::MethodOverride

    # The process's Runtime, made on first use in each worker (after Falcon forks). Kept outside the
    # class's own state, as the app is frozen once its routes are set up.
    RUNTIME = []

    def self.runtime
      RUNTIME[0] ||= Runtime.new
    end

    def runtime = self.class.runtime
    def repo = runtime.repo
    def db = runtime.db
    def secrets = runtime.secrets

    SECURITY_HEADERS = { "X-Frame-Options" => "SAMEORIGIN", "X-XSS-Protection" => "0", "X-Content-Type-Options" => "nosniff",
      "X-Permitted-Cross-Domain-Policies" => "none", "Referrer-Policy" => "strict-origin-when-cross-origin" }.freeze

    # Compared against when the email has no active user (or no password): a digest of a random
    # password, precomputed at the cost the users' digests have (12, Rails' default).
    UNKNOWN_USER_DIGEST = BCrypt::Password.new("$2a$12$CCILrNFgKCoDKYCgpR.QauoPb2m01RTf0JQv.L9TVMAx3A9INQc9a")

    CHECK_CACHES = ENV["CAMPFIRE_CHECK_CACHES"]

    route do |r|
      @matched = false
      begin
        before_action
        routes(r)
      rescue RecordInvalid
        @matched = true
        without_security_headers
        without_version_headers
        status 422
        headers "Content-Type" => "text/html; charset=utf-8"
        respond File.read(File.join(ROOT, "public/422.html"))
      rescue StandardError => error
        warn "#{error.class}: #{error.message}\n#{error.backtrace&.first(10)&.join("\n")}"
        @matched = true
        headers "Content-Type" => "text/html; charset=utf-8"
        status 500
        respond File.read(File.join(ROOT, "public/500.html"))
      end
    end

    # The routing tree. Paths match whole (a terminal matcher consumes the rest of the path), and
    # within a branch the first match wins, so catch-alls such as rooms#show come last.
    def routes(r)
      r.root { run :get_root }
      r.get("up") { run :get_up }
      r.get(/(?:404|422|500|502)\.html|robots\.txt/) { run :get_html_robots_txt }

      r.on "session" do
        r.get("new") { run :get_session_new }
        r.on "transfers", String do |id|
          route_param "id", id
          r.get(true) { run :get_session_transfers_id }
          r.put(true) { run :put_session_transfers_id }
        end
        r.is do
          r.post { run :post_session }
          r.delete { run :delete_session }
        end
      end

      r.is "first_run" do
        r.get { run :get_first_run }
        r.post { run :post_first_run }
      end

      r.is "join", String do |join_code|
        route_param "join_code", join_code
        r.get { run :get_join_join_code }
        r.post { run :post_join_join_code }
      end

      r.on "rooms" do
        r.get(true) { run :get_rooms }
        r.get(/(\d+)(?:\/@(\d+))?/) { |room_id, message_id| run :get_rooms_id, room_id, message_id }
        r.get(/(\d+)\/messages/) { |room_id| run :get_rooms_id_messages, room_id }
        r.post(/(\d+)\/messages/) { |room_id| run :post_rooms_id_messages, room_id }
        r.get(/(opens|closeds)\/new/) { |kind| run :get_rooms_kind_new, kind }
        r.get(/(opens|closeds)\/(\d+)\/edit/) { |kind, id| run :get_rooms_kind_id_edit, kind, id }
        r.get(/(opens|closeds)\/(\d+)/) { |kind, id| run :get_rooms_kind_id, kind, id }
        r.post(/(opens|closeds)/) { |kind| run :post_rooms_kind, kind }
        r.patch(/(opens|closeds)\/(\d+)/) { |kind, id| run :patch_rooms_kind_id, kind, id }
        r.get("directs/new") { run :get_rooms_directs_new }
        r.post("directs") { run :post_rooms_directs }
        r.get(/directs\/(\d+)\/edit/) { |id| run :get_rooms_directs_id_edit, id }
        r.get(/directs\/(\d+)/) { |id| run :get_rooms_directs_id, id }
        r.delete(/(?:directs\/)?(\d+)/) { |id| run :delete_rooms_id, id }
        # The bot API: /rooms/:room_id/:bot_key/messages
        r.get(/(\d+)\/(\d+-[A-Za-z0-9]+)\/messages(?:\.json)?/) { |room_id, bot_key| run :get_rooms_id_bot_messages, room_id, bot_key }
        r.post(/(\d+)\/(\d+-[A-Za-z0-9]+)\/messages(?:\.json)?/) { |room_id, bot_key| run :post_rooms_id_bot_messages, room_id, bot_key }
        r.is(/(\d+)\/(\d+-[A-Za-z0-9]+)\/messages\/(\d+)(?:\.json)?/) do |room_id, bot_key, id|
          r.put { run :update_rooms_id_bot_messages_id, room_id, bot_key, id }
          r.patch { run :update_rooms_id_bot_messages_id, room_id, bot_key, id }
          r.delete { run :delete_rooms_id_bot_messages_id, room_id, bot_key, id }
        end
        r.post(/(\d+)\/(\d+-[A-Za-z0-9]+)\/messages\/(\d+)\/boosts(?:\.json)?/) { |room_id, bot_key, message_id| run :post_rooms_id_bot_messages_id_boosts, room_id, bot_key, message_id }
        r.delete(/(\d+)\/(\d+-[A-Za-z0-9]+)\/messages\/(\d+)\/boosts\/(\d+)(?:\.json)?/) { |room_id, bot_key, message_id, id| run :delete_rooms_id_bot_messages_id_boosts_id, room_id, bot_key, message_id, id }
        r.is(/(\d+)\/involvement/) do |room_id|
          r.get { run :get_rooms_id_involvement, room_id }
          r.put { run :put_rooms_id_involvement, room_id }
        end
        r.get(/(\d+)\/messages\/(\d+)\/edit/) { |room_id, id| run :get_rooms_id_messages_id_edit, room_id, id }
        r.is(/(\d+)\/messages\/(\d+)/) do |room_id, id|
          r.get { run :get_rooms_id_messages_id, room_id, id }
          r.patch { run :patch_rooms_id_messages_id, room_id, id }
          r.delete { run :delete_rooms_id_messages_id, room_id, id }
        end
        r.get(/(\d+)\/refresh/) { |room_id| run :get_rooms_id_refresh, room_id }
        # rooms#show takes any segment as the id ("abc" is 0, "12abc" is 12), after the named routes.
        r.get(/([^\/]+)/) { |id| run :get_rooms_any, id }
      end

      # /account.:format: Rails' account path helper puts the account's id where a format goes.
      r.is(/account(?:\.\d+)?/) do
        r.patch { run :update_account }
        r.put { run :update_account }
      end

      r.on "account" do
        r.get("edit") { run :get_account_edit }
        r.get(/users(?:\.turbo_stream)?/) { run :get_account_users }
        r.is(/users\/(\d+)/) do |id|
          r.patch { run :patch_account_users_id, id }
          r.delete { run :delete_account_users_id, id }
        end
        r.post("join_code") { run :post_account_join_code }
        r.get("custom_styles/edit") { run :get_account_custom_styles_edit }
        r.patch("custom_styles") { run :patch_account_custom_styles }
        r.is "logo" do
          r.get { run :get_account_logo }
          r.delete { run :delete_account_logo }
        end
        r.is "bots" do
          r.get { run :get_account_bots }
          r.post { run :post_account_bots }
        end
        r.get("bots/new") { run :get_account_bots_new }
        r.get(/bots\/(\d+)\/edit/) { |id| run :get_account_bots_id_edit, id }
        r.is(/bots\/(\d+)/) do |id|
          r.patch { run :patch_account_bots_id, id }
          r.delete { run :delete_account_bots_id, id }
        end
        r.put(/bots\/(\d+)\/key/) { |id| run :put_account_bots_id_key, id }
      end

      r.get(/autocompletable\/users(\.json)?/) { |json| run :get_autocompletable_users, json }
      r.get(/webmanifest(?:\.json)?/) { run :get_webmanifest }
      r.get(/service-worker(?:\.js)?/) { run :get_service_worker }
      r.post("unfurl_link") { run :post_unfurl_link }

      r.on "users" do
        r.is "me/push_subscriptions" do
          r.get { run :get_users_me_push_subscriptions }
          r.post { run :post_users_me_push_subscriptions }
        end
        r.delete(/me\/push_subscriptions\/(\d+)/) { |id| run :delete_users_me_push_subscriptions_id, id }
        r.post(/me\/push_subscriptions\/(\d+)\/test_notifications/) { |id| run :post_users_me_push_subscriptions_id_test_notifications, id }
        r.get(/(\d+)/) { |id| run :get_users_id, id }
        r.is "me/profile" do
          r.get { run :get_users_me_profile }
          r.patch { run :patch_users_me_profile }
        end
        r.delete(/(?:me|\d+)\/avatar/) { run :delete_users_who_avatar }
        r.is(/(\d+)\/ban/) do |id|
          r.post { run :post_users_id_ban, id }
          r.delete { run :delete_users_id_ban, id }
        end
        r.get(/(?:me|\d+)\/sidebar/) { run :get_users_who_sidebar }
        r.get(String, "avatar") do |token|
          route_param "token", token
          run :get_users_token_avatar
        end
      end

      r.on "messages" do
        r.is(/(\d+)\/boosts/) do |message_id|
          r.get { run :get_messages_id_boosts, message_id }
          r.post { run :post_messages_id_boosts, message_id }
        end
        r.get(/(\d+)\/boosts\/new/) { |message_id| run :get_messages_id_boosts_new, message_id }
        r.delete(/(\d+)\/boosts\/(\d+)/) { |message_id, id| run :delete_messages_id_boosts_id, message_id, id }
      end

      r.on "searches" do
        r.get(true) { run :get_searches }
        r.post(true) { run :post_searches }
        r.delete("clear") { run :delete_searches_clear }
      end

      r.get "qr_code", String do |id|
        route_param "id", id
        run :get_qr_code_id
      end

      r.on "rails/active_storage" do
        r.get(/blobs\/redirect\/([^\/]+)\/.*/) do |signed_id|
          route_param "signed_id", signed_id
          run :get_rails_active_storage_blobs_redirect_signed_id
        end
        r.get(/representations\/redirect\/([^\/]+)\/([^\/]+)\/.*/) do |signed_blob_id, variation_key|
          route_param "signed_blob_id", signed_blob_id
          route_param "variation_key", variation_key
          run :get_rails_active_storage_representations_redirect_signed_blob_id_variation_key
        end
        r.get(/disk\/([^\/]+)\/.*/) do |encoded_key|
          route_param "encoded_key", encoded_key
          run :get_rails_active_storage_disk_encoded_key
        end
      end
    end

    # A matched route's handler.
    def run(handler, *args)
      @matched = true
      public_send(handler, *args)
    end

    # A path segment captured as a named parameter, decoded as Rails decodes path parameters.
    def route_param(name, value)
      (@route_params ||= {})[name] = Rack::Utils.unescape_path(value)
    end

    # The request's parameters, query and form, with the path's named ones; strings are UTF-8.
    def params
      @params ||= begin
        params = request.params
        force_utf8(params)
        @route_params ? params.merge(@route_params) : params
      end
    end

    def force_utf8(value)
      case value
      when String then value.force_encoding(Encoding::UTF_8) unless value.frozen?
      when Hash then value.each_value { force_utf8(it) }
      when Array then value.each { force_utf8(it) }
      end
      value
    end

    # ApplicationController's shared steps, before any route: reads cached from an earlier request
    # are dropped if the database has changed since; ActionDispatch's default headers on every
    # controller response and ApplicationController's VersionHeaders (a before_action after
    # authentication: see require_authentication!); then BlockBannedRequests, the first of
    # ApplicationController's checks. AllowBrowser is the last of them: see browser_gate!.
    def before_action
      db.check_for_changes
      @page_cache_version = db.generation # captured before authentication (PageCache)
      headers SECURITY_HEADERS
      headers "X-Version" => runtime.app_version, "X-Rev" => runtime.git_revision.to_s
      return if request.path_info.start_with?("/rails/active_storage", "/up")
      head_response(429) if !(request.get? || request.head?) && db.value("SELECT 1 FROM bans WHERE ip_address = ? LIMIT 1", remote_ip)
    end

    # The end of every request: the handler's value as the body (or the public 404 page when no
    # route matched), then ActionDispatch::Response's default Cache-Control (revalidation only for
    # responses with an ETag or Last-Modified, which Rack::ETag adds to 200s; no-cache for the rest).
    def respond(result)
      case result
      when String, Integer then result = [ result ]
      end
      if result.is_a?(Array) && result.first.is_a?(Integer)
        status result[0]
        headers result[1] if result.size > 2
        result_body(result[-1]) if result.size > 1
      elsif result.respond_to?(:each)
        result_body(result)
      end

      response_status = status
      if response.headers["Cache-Control"] == "max-age=0, private, must-revalidate" && response_status != 200
        response.headers["Cache-Control"] = "no-cache"
      end
      response.headers["Cache-Control"] ||= "no-cache" if response_status == 204 # head :no_content

      not_found_page unless @matched
      throw :halt, response.finish
    end

    # A new body drops any Content-Length set for an earlier one (a file's own stays, and a HEAD
    # response keeps the length of the body it doesn't send); string bodies are counted again when
    # the response finishes.
    def result_body(body)
      response.headers.delete("Content-Length") unless request.head? || body.is_a?(Rack::Files::BaseIterator)
      response.result_body = body.is_a?(String) ? [ body ] : body
    end

    # Unmatched paths get the static 404 page, as ActionDispatch::PublicExceptions serves it: no
    # controller ran, so none of its headers.
    def not_found_page
      without_security_headers
      without_version_headers
      status 404
      headers "Content-Type" => "text/html; charset=UTF-8"
      result_body File.read(File.join(ROOT, "public/404.html"))
    end

    # ---- Response helpers

    def headers(hash = nil)
      hash&.each { |name, value| response.headers[name] = value }
      response.headers
    end

    def status(code = nil)
      response.status = code if code
      response.status || 200
    end

    def env = request.env

    # Ends the request with a status, headers and body (any of them), as a Rails head or render
    # from a before-action does.
    def halt(*result)
      @matched = true # a halt answers the request, even from the before-action (a banned IP's 429)
      respond(result.size == 1 ? result.first : result)
    end

    # A weak or strong ETag, answering a matching If-None-Match with 304.
    def etag(value, kind: :strong)
      value = %("#{value}")
      value = "W/#{value}" if kind == :weak
      response.headers["ETag"] = value
      return unless status.between?(200, 299) || status == 304
      matches = ->(list) { list.to_s.split(",").map(&:strip).include?(value) }
      halt(request.get? || request.head? ? 304 : 412) if matches.(env["HTTP_IF_NONE_MATCH"])
      halt 412 if env["HTTP_IF_MATCH"] && !matches.(env["HTTP_IF_MATCH"])
    end

    # The request body as the bot API reads it (Rails' request.raw_post). A form-encoded body has
    # already been read by Rack::MethodOverride, which keeps the bytes it parsed.
    def raw_body
      raw = env["rack.request.form_vars"] || (request.body.rewind; request.body.read)
      raw.to_s.dup.force_encoding(Encoding::UTF_8)
    end

    # A file from disk, with Rack::Files' Last-Modified, conditional and byte-range handling. Only
    # an inline file (no disposition) is sent here.
    def send_file(path, type:, disposition: nil)
      headers "Content-Type" => text_type?(type) ? "#{type};charset=utf-8" : type
      status_code, file_headers, body = Rack::Files.new(File.dirname(path)).serving(request, path)
      file_headers.each { |name, value| response.headers[name] ||= value }
      response.headers["Content-Length"] = file_headers["content-length"]
      halt status_code, body
    end

    def text_type?(type) = type.start_with?("text/") || %w[ application/javascript application/xml application/xhtml+xml ].include?(type)

    # The Accept header's most preferred media type: highest q, then the most specific.
    def preferred_accept
      accept = env["HTTP_ACCEPT"].to_s
      return "*/*" if accept.empty?
      accept.scan(ACCEPT_ENTRY).map { AcceptEntry.new(it) }.sort.first&.type
    end

    ACCEPT_PARAM = /\s*[\w.]+=(?:[\w.]+|"(?:[^"\\]|\\.)*")?\s*/
    ACCEPT_ENTRY = %r{(?:(?:\w+|\*)/(?:\w+(?:\.|-|\+)?|\*)*)\s*(?:;#{ACCEPT_PARAM})*}

    class AcceptEntry
      attr_reader :type, :priority

      def initialize(entry)
        params = entry.scan(ACCEPT_PARAM).to_h { it.strip.split("=", 2) }
        @type = entry[/[^;]+/].delete(" ")
        @priority = [ (params.delete("q") || 1.0).to_f, -@type.count("*"), params.size ]
      end

      def <=>(other) = other.priority <=> priority
    end

    # ---- Handlers, one per route

    # Finished sidebars, kept by everything they're rendered from: the database (the read cache's
    # generation), the user, and the request's host, user agent, frame and Accept. The Elixir port
    # keeps its sidebar the same way (lib/campfire/sidebar.ex: the HTML until a table it reads
    # changes, skipping the queries too). A sidebar with a flash isn't kept. With
    # CAMPFIRE_CHECK_CACHES=1 a hit is rendered again and compared.
    KEPT_SIDEBARS = {}
    KEPT_SIDEBARS_LIMIT = 1024
    KeptSidebar = Data.define(:body, :digest, :headers)
    
    # GET "/up"
    def get_up
      without_version_headers
      headers "Cache-Control" => "max-age=0, private, must-revalidate", "Content-Type" => "text/html; charset=utf-8"
      headers "Vary" => "Accept" if vary_by_accept?
      %(<!DOCTYPE html><html><body style="background-color: green"></body></html>)
    end

    # GET %r{/(404|422|500|502)\.html|/robots\.txt}
    def get_html_robots_txt
      path = File.join(ROOT, "public", request.path_info)
      without_security_headers
      without_version_headers
      halt 304, {}, [] if request.env["HTTP_IF_MODIFIED_SINCE"] == File.mtime(path).httpdate # Rack::Files
      headers "Cache-Control" => "public, max-age=2592000", "Last-Modified" => File.mtime(path).httpdate,
        "Content-Type" => request.path_info.end_with?(".txt") ? "text/plain" : "text/html"
      File.read(path)
    end

    # GET "/session/new"
    def get_session_new
      browser_gate! # an unauthenticated ApplicationController action
      # SessionsController#ensure_user_exists
      return redirect(url_for("/first_run")) unless db.value("SELECT 1 FROM users LIMIT 1")
      render_page(:sessions_new, page_title: "Sign in", head: %(<meta name="turbo-visit-control" content="reload">), email_address: params["email_address"])
    end

    # POST "/session"
    def post_session
      verify_same_origin!
      return render_sign_in_rejection(429) if RateLimit.exceeded?("sessions:#{remote_ip}", limit: 10, within: 180)
      user = repo.active_user_by_email(params["email_address"].to_s)
      # User.active.authenticate_by runs one bcrypt check even when no user has the email, so a
      # failed sign-in takes as long whether or not the address has an account.
      digest = user&.password_digest ? BCrypt::Password.new(user.password_digest) : UNKNOWN_USER_DIGEST
      if digest == params["password"].to_s && user&.password_digest
        start_new_session_for(user)
        redirect_after_authentication
      else
        render_sign_in_rejection(401)
      end
    end

    # GET "/first_run"
    def get_first_run
      browser_gate! # an unauthenticated ApplicationController action
      return redirect(url_for("/")) if runtime.account
      render_page(:first_runs_show, page_title: "Set up Campfire", body_class: "signup")
    end

    # POST "/first_run"
    def post_first_run
      verify_same_origin!
      return redirect(url_for("/")) if runtime.account
      user = Users.first_run(self, params["user"] || {})
      start_new_session_for(user)
      redirect url_for("/")
    end

    # GET "/join/:join_code"
    def get_join_join_code
      browser_gate! # an unauthenticated ApplicationController action
      return redirect(url_for("/")) if restore_authentication
      head_response(404) unless runtime.account.join_code == params["join_code"]
      view = build_view(join_code: params["join_code"])
      render_layout(view, page_title: "Sign up", body_class: "signup", nav: view.tpl_users_new_nav, main: view.tpl_users_new)
    end

    # POST "/join/:join_code"
    def post_join_join_code
      verify_same_origin!
      return redirect(url_for("/")) if restore_authentication
      head_response(404) unless runtime.account.join_code == params["join_code"]
      attributes = params["user"] || {}
      if (user = Users.create(self, attributes))
        start_new_session_for(user)
        redirect url_for("/")
      else
        redirect url_for("/session/new?#{URI.encode_www_form(email_address: attributes["email_address"])}")
      end
    end

    # GET "/session/transfers/:id"
    def get_session_transfers_id
      browser_gate! # an unauthenticated ApplicationController action
      view = build_view(request_path: request.path)
      render_layout(view, main: view.tpl_sessions_transfer)
    end

    # PUT "/session/transfers/:id"
    def put_session_transfers_id
      verify_same_origin!
      user_id = secrets.find_signed_id(params["id"], "user/transfer")
      user = user_id && repo.user(user_id)
      head_response(400, in_action: true) unless user&.active?
      start_new_session_for(user)
      redirect_after_authentication
    end

    # DELETE "/session"
    def delete_session
      require_authentication!
      verify_same_origin!
      # remove_push_subscription: this device stops getting the user's notifications.
      if (endpoint = params["push_subscription_endpoint"])
        db.transaction { |w| w.run("DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?", endpoint.to_s, current_user.id) }
      end
      db.transaction { |w| w.run("DELETE FROM sessions WHERE id = ?", @session.id) }
      Broadcasts.disconnect_user(current_user.id, reconnect: true) # Authentication#disconnect_remote_connections
      response.delete_cookie("session_token", path: "/")
      response.delete_cookie("_campfire_session", path: "/")
      redirect url_for("/")
    end

    # GET "/"
    def get_root
      require_authentication!
      room = last_room_visited
      room ? redirect(url_for("/rooms/#{room.id}")) : render_welcome
    end

    # GET "/rooms"
    def get_rooms
      require_authentication!
      room = repo.user_last_room(current_user.id)
      redirect url_for("/rooms/#{room.id}")
    end

    # GET %r{/rooms/(\d+)(?:/@(\d+))?}
    def get_rooms_id(room_id, message_id)
      require_authentication!
      room = repo.user_room(current_user.id, room_id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room

      remember_last_room_visited(room)
      cached_page { render_room(room, find_room_messages(room, message_id)) }
    end

    # GET %r{/rooms/(\d+)/messages}
    def get_rooms_id_messages(room_id)
      require_authentication!
      room = room_scoped!(room_id)
      cached_page { messages_index(room) }
    end

    # MessagesController#index, after authentication and the room check.
    def messages_index(room)
      messages =
        if (before = params["before"]).to_s != ""
          anchor = repo.room_message(room.id, before.to_i) or record_not_found!
          repo.page_before(room.id, anchor.created_at)
        elsif (after = params["after"]).to_s != ""
          anchor = repo.room_message(room.id, after.to_i) or record_not_found!
          repo.page_after(room.id, anchor.created_at)
        else
          repo.last_page(room.id)
        end

      if messages.empty?
        headers "Cache-Control" => "no-cache"
        status 204
        return ""
      end

      etag_for_messages(messages)
      html_headers
      # fresh_when @messages: the newest updated_at is the Last-Modified.
      headers "Last-Modified" => messages.map { TimeFormat.parse(it.updated_at) }.max.httpdate
      messages_page(messages)
    end

    # POST %r{/rooms/(\d+)/messages}
    def post_rooms_id_messages(room_id)
      require_authentication!
      verify_same_origin!
      membership = repo.membership(current_user.id, room_id.to_i)
      return render_room_not_found unless membership

      room = repo.room(membership.room_id)
      message = Messages.create(self, room: room, creator: current_user, params: params["message"] || {})
      view = message_views([ message ]).first
      Messages.after_create(self, room, message, view)

      html_headers("text/vnd.turbo-stream.html")
      %(<turbo-stream action="append" target="messages_#{room.param_key}_#{room.id}"><template>#{build_view.render_message_cached(view)}</template></turbo-stream>)
    end

    # GET %r{/rooms/(opens|closeds)/new}
    def get_rooms_kind_new(kind)
      require_authentication!
      head_response(403) unless can_create_rooms?
      render_room_settings(kind.chomp("s"), nil)
    end

    # GET %r{/rooms/(opens|closeds)/(\d+)/edit}
    def get_rooms_kind_id_edit(kind, id)
      require_authentication!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room && !room.direct?
      render_room_settings(kind.chomp("s"), room)
    end

    # GET %r{/rooms/(opens|closeds)/(\d+)}
    def get_rooms_kind_id(_kind, id)
      require_authentication!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room && !room.direct?
      remember_last_room_visited(room)
      redirect url_for("/rooms/#{room.id}")
    end

    # POST %r{/rooms/(opens|closeds)}
    def post_rooms_kind(kind)
      require_authentication!
      verify_same_origin!
      head_response(403) unless can_create_rooms?
      room = Rooms.create(self, kind == "opens" ? "Rooms::Open" : "Rooms::Closed", (params["room"] || {})["name"].to_s, Array(params["user_ids"]))
      redirect url_for("/rooms/#{room.id}")
    end

    # PATCH %r{/rooms/(opens|closeds)/(\d+)}
    def patch_rooms_kind_id(kind, id)
      require_authentication!
      verify_same_origin!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room && !room.direct?
      head_response(403) unless current_user.can_administer?(room)
      room = Rooms.update(self, room, kind == "opens" ? "Rooms::Open" : "Rooms::Closed", (params["room"] || {})["name"], Array(params["user_ids"]))
      redirect url_for("/rooms/#{room.id}")
    end

    # GET "/rooms/directs/new"
    def get_rooms_directs_new
      require_authentication!
      view = build_view
      render_layout(view, main: view.tpl_rooms_direct_new)
    end

    # POST "/rooms/directs"
    def post_rooms_directs
      require_authentication!
      verify_same_origin!
      room = Rooms.find_or_create_direct(self, (Array(params["user_ids"]).map(&:to_i) + [ current_user.id ]).uniq)
      redirect url_for("/rooms/#{room.id}")
    end

    # GET %r{/rooms/directs/(\d+)/edit}
    def get_rooms_directs_id_edit(id)
      require_authentication!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room&.direct?
      users = repo.room_users(room.id)
      members = users.size > 1 ? users.reject { it.id == current_user.id } : users
      view = build_view(room: room, members: members, last_room_visited: last_room_visited)
      render_layout(view, page_title: "Edit settings for #{view.room_display_name(room)}", nav: view.tpl_rooms_settings_nav, main: view.tpl_rooms_direct_edit)
    end

    # GET %r{/rooms/directs/(\d+)}
    def get_rooms_directs_id(id)
      require_authentication!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room&.direct?
      redirect url_for("/rooms/#{room.id}")
    end

    # DELETE %r{/rooms(?:/directs)?/(\d+)}
    def delete_rooms_id(id)
      require_authentication!
      verify_same_origin!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room && (room.direct? == request.path_info.include?("/directs/"))
      head_response(403) unless room.direct? || current_user.can_administer?(room)
      Rooms.destroy(self, room)
      redirect url_for("/")
    end

    # GET "/account/edit"
    def get_account_edit
      require_authentication!
      statuses = current_user.can_administer? ? "0, 2" : "0"
      users = db.rows("SELECT #{User.columns} FROM users WHERE status IN (#{statuses}) AND role != 2 ORDER BY LOWER(name)").map { User.new(*it) }
      administrators, members = users.partition(&:administrator?)
      view = build_view(administrators: administrators, members: members, next_page: users.size > 500 ? 2 : nil,
        last_room_visited: last_room_visited)
      footer = %(<div class="txt-align-center center margin-block-double txt-subtle">Campfire&trade; version <span class="version-badge">#{HTML.h(runtime.app_version)}</span></div>)
      render_layout(view, page_title: "Account settings", nav: view.tpl_accounts_edit_nav, main: view.tpl_accounts_edit, footer: footer)
    end

    # GET %r{/account/users(?:\.turbo_stream)?}
    def get_account_users
      require_authentication!
      page = [ params["page"].to_i, 1 ].max
      users = db.rows("SELECT #{User.columns} FROM users WHERE status = 0 AND role != 2 ORDER BY LOWER(name) LIMIT 500 OFFSET ?", (page - 1) * 500).map { User.new(*it) }
      more = db.value("SELECT COUNT(*) FROM users WHERE status = 0 AND role != 2") > page * 500
      view = build_view
      html = %(<turbo-stream action="replace" target="next_page_container"><template>#{users.map { view.render_account_user(it) }.join}</template></turbo-stream>)
      html << %(<turbo-stream action="append" target="account_users"><template><turbo-frame loading="lazy" src="/account/users.turbo_stream?page=#{page + 1}" class="flex center" id="next_page_container">\n  <div class="spinner center"></div>\n</turbo-frame></template></turbo-stream>) if more
      html_headers("text/vnd.turbo-stream.html")
      html
    end

    # PATCH %r{/account/users/(\d+)}
    def patch_account_users_id(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      user = repo.user(id.to_i)
      record_not_found! unless user&.active?
      role = %w[ member administrator ].include?((params["user"] || {})["role"]) ? params["user"]["role"] : "member"
      db.transaction { |w| w.run("UPDATE users SET role = ?, updated_at = ? WHERE id = ?", role == "administrator" ? 1 : 0, TimeFormat.now_text, user.id) }
      redirect url_for("/account/edit")
    end

    # DELETE %r{/account/users/(\d+)}
    def delete_account_users_id(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      user = repo.user(id.to_i)
      record_not_found! unless user&.active?
      Accounts.deactivate(self, user)
      redirect url_for("/account/edit")
    end

    # POST "/account/join_code"
    def post_account_join_code
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      code = SecureRandom.alphanumeric(12).scan(/.{4}/).join("-")
      db.transaction { |w| w.run("UPDATE accounts SET join_code = ?, updated_at = ?", code, TimeFormat.now_text) }
      redirect url_for("/account/edit")
    end

    # GET "/account/custom_styles/edit"
    def get_account_custom_styles_edit
      require_authentication!
      head_response(403) unless current_user.can_administer?
      view = build_view
      render_layout(view, page_title: "Custom styles", nav: view.tpl_accounts_custom_styles_nav, main: view.tpl_accounts_custom_styles)
    end

    # PATCH "/account/custom_styles"
    def patch_account_custom_styles
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      db.transaction { |w| w.run("UPDATE accounts SET custom_styles = ?, updated_at = ?", (params["account"] || {})["custom_styles"], TimeFormat.now_text) }
      redirect_with_notice("/account/custom_styles/edit", "✓")
    end

    # DELETE "/account/logo"
    def delete_account_logo
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      db.transaction do |w|
        w.run("DELETE FROM active_storage_attachments WHERE record_type = 'Account' AND name = 'logo'")
        w.run("UPDATE accounts SET updated_at = ?", TimeFormat.now_text)
      end
      redirect url_for("/account/edit")
    end

    # GET "/account/bots"
    def get_account_bots
      require_authentication!
      head_response(403) unless current_user.can_administer?
      bots = db.rows("SELECT #{User.columns} FROM users WHERE status = 0 AND role = 2 ORDER BY LOWER(name)").map { User.new(*it) }
      bots = bots.map do |bot|
        rooms = db.rows(<<~SQL, bot.id).map { Room.new(*it) }
          SELECT #{Room.columns} FROM rooms INNER JOIN memberships ON rooms.id = memberships.room_id
          WHERE memberships.user_id = ? AND rooms.type != 'Rooms::Direct' ORDER BY LOWER(name)
        SQL
        [ bot, rooms ]
      end
      view = build_view(bots: bots, back_path: "/account/edit")
      render_layout(view, page_title: "Chat bots", nav: view.tpl_bots_back_nav, main: view.tpl_bots_index)
    end

    # GET "/account/bots/new"
    def get_account_bots_new
      require_authentication!
      head_response(403) unless current_user.can_administer?
      view = build_view(bot: nil, bot_avatar_src: Assets.path("default-bot-avatar.svg"), webhook_url: nil, back_path: "/account/bots")
      render_layout(view, page_title: "New chat bot", nav: view.tpl_bots_back_nav, main: view.tpl_bots_form)
    end

    # GET %r{/account/bots/(\d+)/edit}
    def get_account_bots_id_edit(id)
      require_authentication!
      head_response(403) unless current_user.can_administer?
      bot = active_bot!(id)
      avatar = repo.attachment_blob("User", bot.id, "avatar")
      view = build_view(bot: bot, bot_avatar_src: avatar ? url_for(Storage.blob_path(runtime, avatar)) : Assets.path("default-bot-avatar.svg"),
        webhook_url: db.value("SELECT url FROM webhooks WHERE user_id = ? LIMIT 1", bot.id), back_path: "/account/bots")
      render_layout(view, page_title: "Edit bot", nav: view.tpl_bots_back_nav, main: view.tpl_bots_form)
    end

    # POST "/account/bots"
    def post_account_bots
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      BotAccounts.create(self, params["user"] || {})
      redirect url_for("/account/bots")
    end

    # PATCH %r{/account/bots/(\d+)}
    def patch_account_bots_id(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      BotAccounts.update(self, active_bot!(id), params["user"] || {})
      redirect url_for("/account/bots")
    end

    # PUT %r{/account/bots/(\d+)/key}
    def put_account_bots_id_key(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      bot = active_bot!(id)
      db.transaction { |w| w.run("UPDATE users SET bot_token = ?, updated_at = ? WHERE id = ?", SecureRandom.alphanumeric(12), TimeFormat.now_text, bot.id) }
      redirect url_for("/account/bots")
    end

    # DELETE %r{/account/bots/(\d+)}
    def delete_account_bots_id(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      Accounts.deactivate(self, active_bot!(id))
      redirect url_for("/account/bots")
    end

    # GET %r{/autocompletable/users(\.json)?}
    def get_autocompletable_users(json)
      require_authentication!
      query = params["filter"].to_s.empty? ? params["query"].to_s : params["filter"].to_s
      users = Autocomplete.users(self, params["room_id"], query)
      if json || preferred_accept == "application/json"
        headers "Content-Type" => "application/json; charset=utf-8"
        RailsJSON.generate(users.map { { name: HTML.h(it.name), value: it.id, avatar_url: url_for(build_view.avatar_path(it)), sgid: secrets.attachable_sgid("User", it.id) } })
      else
        view = build_view
        html_headers
        users.map { Autocomplete.prompt_item(view, it) }.join << "\n"
      end
    end

    # GET %r{/webmanifest(\.json)?}
    def get_webmanifest
      browser_gate! # an unauthenticated ApplicationController action
      account = runtime.account
      view = build_view
      headers "Content-Type" => "application/json; charset=utf-8", "Cache-Control" => "max-age=0, private, must-revalidate"
      Pwa.manifest(view, account, base_url)
    end

    # GET %r{/service-worker(\.js)?}
    def get_service_worker
      browser_gate! # an unauthenticated ApplicationController action
      headers "Content-Type" => "text/javascript; charset=utf-8", "Cache-Control" => "max-age=0, private, must-revalidate"
      File.read(File.join(ROOT, "public/service-worker.js"))
    end

    # GET "/users/me/push_subscriptions"
    def get_users_me_push_subscriptions
      require_authentication!
      subscriptions = db.rows("SELECT id, endpoint, user_agent FROM push_subscriptions WHERE user_id = ?", current_user.id)
      view = build_view(subscriptions: subscriptions, last_room_visited: last_room_visited)
      render_layout(view, page_title: "Push notification subscriptions", nav: view.tpl_rooms_settings_nav, main: view.tpl_push_index)
    end

    # POST "/users/me/push_subscriptions"
    def post_users_me_push_subscriptions
      require_authentication!
      verify_same_origin!
      attributes = params["push_subscription"] || {}
      halt 400, "" if attributes.empty?
      status PushSubscriptions.create(self, attributes) ? 200 : 422
      ""
    end

    # DELETE %r{/users/me/push_subscriptions/(\d+)}
    def delete_users_me_push_subscriptions_id(id)
      require_authentication!
      verify_same_origin!
      db.transaction { |w| w.run("DELETE FROM push_subscriptions WHERE id = ? AND user_id = ?", id.to_i, current_user.id) }
      redirect url_for("/users/me/push_subscriptions")
    end

    # POST %r{/users/me/push_subscriptions/(\d+)/test_notifications}
    def post_users_me_push_subscriptions_id_test_notifications(id)
      require_authentication!
      verify_same_origin!
      row = db.row("SELECT endpoint, p256dh_key, auth_key FROM push_subscriptions WHERE id = ? AND user_id = ?", id.to_i, current_user.id) or record_not_found!
      payload = { title: "Campfire Test", body: SecureRandom.uuid, path: url_for("/users/me/push_subscriptions") }
      badge = db.value("SELECT COUNT(*) FROM memberships WHERE user_id = ? AND unread_at IS NOT NULL", current_user.id)
      Push.deliver(runtime, id.to_i, *row, payload, badge) if Push.permitted?(row[0])
      redirect url_for("/users/me/push_subscriptions")
    end

    # POST "/unfurl_link"
    def post_unfurl_link
      require_authentication!
      verify_same_origin!
      halt 400, "" if params["url"].to_s.empty?
      if (metadata = Unfurl.metadata(params["url"].to_s))
        headers "Content-Type" => "application/json; charset=utf-8"
        RailsJSON.generate(metadata)
      else
        status 204
        ""
      end
    end

    # GET %r{/rooms/(\d+)/(\d+-[A-Za-z0-9]+)/messages(?:\.json)?}
    def get_rooms_id_bot_messages(room_id, bot_key)
      bot, room = bot_room!(bot_key, room_id)
      messages =
        if !params["before"].to_s.empty? then repo.page_before(room.id, (repo.room_message(room.id, params["before"].to_i) or record_not_found!).created_at)
        elsif !params["after"].to_s.empty? then repo.page_after(room.id, (repo.room_message(room.id, params["after"].to_i) or record_not_found!).created_at)
        else repo.last_page(room.id)
        end
      headers "X-Total-Count" => repo.room_message_count(room.id).to_s
      if (link = BotApi.next_page_link(self, room, bot_key, messages))
        headers "Link" => link
      end
      headers "Content-Type" => "application/json; charset=utf-8"
      RailsJSON.generate(messages.map { BotApi.message_json(self, it) })
    end

    # POST %r{/rooms/(\d+)/(\d+-[A-Za-z0-9]+)/messages(?:\.json)?}
    def post_rooms_id_bot_messages(room_id, bot_key)
      bot, room = bot_room!(bot_key, room_id)
      @current_user = bot
      attachment = params["attachment"]
      raw = raw_body
      head_response(422) if attachment.to_s.empty? && raw.empty?
      message_params = attachment.is_a?(Hash) ? { "attachment" => attachment } : { "body" => raw }
      message = Messages.create(self, room: room, creator: bot, params: message_params)
      Messages.after_create(self, room, message, message_views([ message ]).first)
      status 201
      headers "Location" => url_for("/messages/#{message.id}")
      ""
    end

    # DELETE %r{/rooms/(\d+)/(\d+-[A-Za-z0-9]+)/messages/(\d+)(?:\.json)?}
    def delete_rooms_id_bot_messages_id(room_id, bot_key, id)
      bot, room = bot_room!(bot_key, room_id)
      message = repo.room_message(room.id, id.to_i) or record_not_found!
      head_response(403) unless bot.can_administer?(message)
      MessageRemoval.destroy(runtime, message)
      Broadcasts.turbo_stream("#{RailsCompat.gid_param(room.type, room.id)}:messages", %(<turbo-stream action="remove" target="message_#{message.client_message_id}"></turbo-stream>))
      status 204
      ""
    end

    # POST %r{/rooms/(\d+)/(\d+-[A-Za-z0-9]+)/messages/(\d+)/boosts(?:\.json)?}
    def post_rooms_id_bot_messages_id_boosts(room_id, bot_key, message_id)
      bot, room = bot_room!(bot_key, room_id)
      @current_user = bot
      message = repo.room_message(room.id, message_id.to_i) or head_response(404)
      content = raw_body
      head_response(422) if content.strip.empty?
      boost = Boosts.create(self, message, content)
      status 201
      headers "Content-Type" => "application/json; charset=utf-8"
      RailsJSON.generate(BotApi.boost_json(self, boost, message))
    end

    # DELETE %r{/rooms/(\d+)/(\d+-[A-Za-z0-9]+)/messages/(\d+)/boosts/(\d+)(?:\.json)?}
    def delete_rooms_id_bot_messages_id_boosts_id(room_id, bot_key, message_id, id)
      bot, room = bot_room!(bot_key, room_id)
      @current_user = bot
      message = repo.room_message(room.id, message_id.to_i) or head_response(404)
      Boosts.destroy(self, message, id.to_i) or head_response(404)
      status 204
      ""
    end

    # GET %r{/users/(\d+)}
    def get_users_id(id)
      require_authentication!
      user = repo.user(id.to_i) or record_not_found!
      view = build_view(user: user)
      render_layout(view, page_title: user.name, nav: view.tpl_users_show_nav, main: view.tpl_users_show)
    end

    # GET "/users/me/profile"
    def get_users_me_profile
      require_authentication!
      memberships = repo.sidebar_memberships(current_user.id, visible_only: false)
      directs, shared = memberships.partition { |_, room| room.direct? }
      view = build_view(user: current_user, direct_memberships: directs, shared_memberships: shared,
        avatar_attached: !repo.attachment_blob("User", current_user.id, "avatar").nil?)
      render_layout(view, page_title: current_user.name, nav: view.tpl_profiles_show_nav, main: view.tpl_profiles_show)
    end

    # PATCH "/users/me/profile"
    def patch_users_me_profile
      require_authentication!
      verify_same_origin!
      attributes = params["user"] || {}
      Profiles.update(self, current_user, attributes)
      redirect_with_notice("/users/me/profile", attributes["avatar"] ? "It may take up to 30 minutes to change everywhere." : "✓")
    end

    # DELETE %r{/users/(me|\d+)/avatar}
    def delete_users_who_avatar
      require_authentication!
      verify_same_origin!
      Profiles.remove_avatar(self, current_user)
      redirect url_for("/users/me/profile")
    end

    # POST %r{/users/(\d+)/ban}
    def post_users_id_ban(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      user = repo.user(id.to_i) or record_not_found!
      Bans.ban(self, user)
      redirect url_for("/users/#{user.id}")
    end

    # DELETE %r{/users/(\d+)/ban}
    def delete_users_id_ban(id)
      require_authentication!
      verify_same_origin!
      head_response(403) unless current_user.can_administer?
      user = repo.user(id.to_i) or record_not_found!
      Bans.unban(self, user)
      redirect url_for("/users/#{user.id}")
    end

    # GET %r{/rooms/(\d+)/involvement}
    def get_rooms_id_involvement(room_id)
      require_authentication!
      membership = repo.membership(current_user.id, room_id.to_i) or record_not_found!
      room = repo.room(membership.room_id)
      view = build_view
      frame = %(<turbo-frame data-controller="turbo-frame" data-action="notifications:ready@window-&gt;turbo-frame#load" data-turbo-frame-url-param="/rooms/#{room.id}/involvement" id="involvement_#{room.param_key}_#{room.id}">\n  #{view.involvement_button(room, membership.involvement)}\n</turbo-frame>)
      render_layout(view, main: frame)
    end

    # PUT %r{/rooms/(\d+)/involvement}
    def put_rooms_id_involvement(room_id)
      require_authentication!
      verify_same_origin!
      membership = repo.membership(current_user.id, room_id.to_i) or record_not_found!
      Involvements.update(self, membership, params["involvement"].to_s)
      redirect url_for("/rooms/#{membership.room_id}/involvement")
    end

    # GET %r{/rooms/(\d+)/messages/(\d+)}
    def get_rooms_id_messages_id(room_id, id)
      require_authentication!
      room = room_scoped!(room_id)
      message = repo.room_message(room.id, id.to_i) or record_not_found!
      view = build_view
      render_layout(view, main: view.render_message_cached(message_views([ message ]).first), frame_layout: false)
    end

    # GET %r{/rooms/(\d+)/messages/(\d+)/edit}
    def get_rooms_id_messages_id_edit(room_id, id)
      require_authentication!
      room = room_scoped!(room_id)
      message = repo.room_message(room.id, id.to_i) or record_not_found!
      head_response(403) unless current_user.can_administer?(message)
      message_view = Messages.views(self, [ message ], cached: false).first
      body = repo.bodies([ message.id ])[message.id]
      view = build_view(view: message_view, message: message, room: room, editor_value: Messages.editor_value(self, body))
      render_layout(view, main: view.tpl_messages_edit, frame_layout: false)
    end

    # PATCH %r{/rooms/(\d+)/messages/(\d+)}
    def patch_rooms_id_messages_id(room_id, id)
      require_authentication!
      verify_same_origin!
      room = room_scoped!(room_id)
      message = repo.room_message(room.id, id.to_i) or record_not_found!
      head_response(403) unless current_user.can_administer?(message)
      message = Messages.update(self, room, message, (params["message"] || {})["body"])
      redirect url_for("/rooms/#{room.id}/messages/#{message.id}")
    end

    # DELETE %r{/rooms/(\d+)/messages/(\d+)}
    def delete_rooms_id_messages_id(room_id, id)
      require_authentication!
      verify_same_origin!
      room = room_scoped!(room_id)
      message = repo.room_message(room.id, id.to_i) or record_not_found!
      head_response(403) unless current_user.can_administer?(message)
      MessageRemoval.destroy(runtime, message)
      remove = %(<turbo-stream action="remove" target="message_#{message.client_message_id}"></turbo-stream>)
      Broadcasts.turbo_stream("#{RailsCompat.gid_param(room.type, room.id)}:messages", remove)
      html_headers("text/vnd.turbo-stream.html")
      remove
    end

    # GET %r{/rooms/(\d+)/refresh}
    def get_rooms_id_refresh(room_id)
      require_authentication!
      # respond_to turbo_stream only
      unless request.env["HTTP_ACCEPT"].to_s.include?("text/vnd.turbo-stream.html")
        without_security_headers
        without_version_headers
        halt 406, { "Content-Type" => "text/html; charset=utf-8" }, ""
      end
      room = room_scoped!(room_id)
      since = TimeFormat.dump(Time.at(0, params["since"].to_i, :millisecond))
      created = repo.messages_created_since(room.id, since)
      updated = repo.messages_updated_since(room.id, since, created.map(&:id))
      view = build_view
      html = +""
      html << %(<turbo-stream action="append" target="messages_#{room.param_key}_#{room.id}"><template>#{message_views(created).map { view.render_message_cached(it) }.join}</template></turbo-stream>) if created.any?
      message_views(updated).each do |message_view|
        html << %(<turbo-stream action="replace" target="message_#{message_view.message.client_message_id}"><template>#{view.render_message_cached(message_view)}</template></turbo-stream>)
      end
      html_headers("text/vnd.turbo-stream.html")
      html.empty? ? "\n" : html # the template's trailing newline when there's nothing to send
    end

    # GET %r{/messages/(\d+)/boosts}
    def get_messages_id_boosts(message_id)
      require_authentication!
      message = reachable_message!(message_id)
      view = build_view
      message_view = Messages.views(self, [ message ], cached: false).first
      render_layout(view, main: view.with(message: message, view: message_view).render_boosts(message_view))
    end

    # GET %r{/messages/(\d+)/boosts/new}
    def get_messages_id_boosts_new(message_id)
      require_authentication!
      message = reachable_message!(message_id)
      view = build_view(message: message)
      render_layout(view, main: view.tpl_boosts_new)
    end

    # POST %r{/messages/(\d+)/boosts}
    def post_messages_id_boosts(message_id)
      require_authentication!
      verify_same_origin!
      message = reachable_message!(message_id)
      Boosts.create(self, message, (params["boost"] || {})["content"].to_s)
      redirect url_for("/messages/#{message.id}/boosts")
    end

    # DELETE %r{/messages/(\d+)/boosts/(\d+)}
    def delete_messages_id_boosts_id(message_id, id)
      require_authentication!
      verify_same_origin!
      message = reachable_message!(message_id)
      Boosts.destroy(self, message, id.to_i) or record_not_found!
      status 204
      ""
    end

    # GET %r{/users/(me|\d+)/sidebar}
    def get_users_who_sidebar
      require_authentication!
      cached_page { kept_sidebar }
    end

    def kept_sidebar
      html_headers
      return render_sidebar if Campfire.rust_caching_only?
      key = [ db.generation, current_user, base_url, request.user_agent, env["HTTP_TURBO_FRAME"], env["HTTP_ACCEPT"] ]
      if flash_now.empty? && (kept = KEPT_SIDEBARS.delete(key))
        KEPT_SIDEBARS[key] = kept
        headers kept.headers
        check_kept("sidebar", kept.body) { render_sidebar } if CHECK_CACHES
      else
        body = render_sidebar
        return body unless flash_now.empty?
        kept_headers = KEPT_HEADERS.filter_map { |name| (value = response.headers[name]) && [ name, value ] }.to_h
        kept = KEPT_SIDEBARS[key] = KeptSidebar.new(body.freeze, Digest::MD5.hexdigest(body), kept_headers)
        KEPT_SIDEBARS.delete(KEPT_SIDEBARS.first[0]) while KEPT_SIDEBARS.size > KEPT_SIDEBARS_LIMIT
      end
      # What the ETag middleware would set, so it doesn't hash the body again.
      headers "ETag" => %(W/"#{kept.digest}")
      env[ETag::BODY_DIGEST] = kept.digest
      kept.body
    end

    # GET "/searches"
    def get_searches
      require_authentication!
      cached_page do
        raw = params["q"]
        query = raw&.gsub(/[^[:word:]]/, " ")
        messages = query.to_s.strip.empty? ? [] : repo.search(current_user.id, query)
        render_search(query.to_s.strip.empty? ? nil : query, raw, messages)
      end
    end

    # POST "/searches"
    def post_searches
      require_authentication!
      verify_same_origin!
      query = params["q"]&.gsub(/[^[:word:]]/, " ")
      Searches.record(self, current_user, query)
      redirect url_for("/searches?q=#{URI.encode_www_form_component(query.to_s)}")
    end

    # DELETE "/searches/clear"
    def delete_searches_clear
      require_authentication!
      verify_same_origin!
      db.transaction { |w| w.run("DELETE FROM searches WHERE user_id = ?", current_user.id) }
      redirect url_for("/searches")
    end

    # GET "/users/:token/avatar"
    def get_users_token_avatar
      without_security_headers
      require_authentication!
      Avatars.show(self, params["token"])
    end

    # GET "/account/logo"
    def get_account_logo
      browser_gate! # an unauthenticated ApplicationController action
      Avatars.account_logo(self)
    end

    # GET "/qr_code/:id"
    def get_qr_code_id
      browser_gate! # an unauthenticated ApplicationController action
      QrCodes.show(self, params["id"])
    end

    # GET "/rails/active_storage/blobs/redirect/:signed_id/*"
    def get_rails_active_storage_blobs_redirect_signed_id
      blob = signed_blob!(params["signed_id"])
      redirect_to_disk(blob, params["disposition"])
    end

    # GET "/rails/active_storage/representations/redirect/:signed_blob_id/:variation_key/*"
    def get_rails_active_storage_representations_redirect_signed_blob_id_variation_key
      blob = signed_blob!(params["signed_blob_id"])
      transformations = Storage.verify(runtime, params["variation_key"], "variation") or active_storage_not_found
      # ActiveStorage::Preview: a video's representation is a variant of its stored preview image.
      if blob.video?
        row = db.row(<<~SQL, blob.id) or active_storage_not_found
          SELECT #{Blob.columns} FROM active_storage_attachments JOIN active_storage_blobs ON active_storage_blobs.id = active_storage_attachments.blob_id
          WHERE active_storage_attachments.record_type = 'ActiveStorage::Blob' AND active_storage_attachments.record_id = ? AND active_storage_attachments.name = 'preview_image' LIMIT 1
        SQL
        blob = Blob.new(*row)
      end
      variant = Uploads.variant_blob(Context.new(runtime), blob, transformations)
      redirect_to_disk(variant, params["disposition"])
    end

    # GET "/rails/active_storage/disk/:encoded_key/*"
    def get_rails_active_storage_disk_encoded_key
      without_version_headers
      key = Storage.verify(runtime, params["encoded_key"], "blob_key") or active_storage_not_found
      path = Storage.path_for(key["key"].to_s)
      active_storage_not_found unless File.file?(path)
      headers "Cache-Control" => "max-age=3600, public", "Content-Disposition" => key["disposition"].to_s
      send_file path, type: key["content_type"] || "application/octet-stream", disposition: nil
    end

    # GET %r{/rooms/([^/]+)}
    def get_rooms_any(id)
      require_authentication!
      room = repo.user_room(current_user.id, id.to_i)
      return redirect_with_alert("/", "Room not found or inaccessible") unless room

      remember_last_room_visited(room)
      render_room(room, find_room_messages(room, nil))
    end

    # PUT/PATCH %r{/rooms/(\d+)/(\d+-[A-Za-z0-9]+)/messages/(\d+)(?:\.json)?}
    def update_rooms_id_bot_messages_id(room_id, bot_key, id)
      bot, room = bot_room!(bot_key, room_id)
      @current_user = bot
      message = repo.room_message(room.id, id.to_i) or record_not_found!
      head_response(403) unless bot.can_administer?(message)
      # Messages::ByBotsController#message_params: the raw request body is the message
      message = Messages.update(self, room, message, raw_body)
      headers "Content-Type" => "application/json; charset=utf-8"
      RailsJSON.generate(BotApi.message_json(self, message))
    end
    
    # ---- Helpers

    def update_account
    require_authentication!
    verify_same_origin!
    head_response(403) unless current_user.can_administer?
    Accounts.update(self, params["account"] || {})
    redirect_with_notice("/account/edit", "✓")
    end

    # CAMPFIRE_CHECK_CACHES=1: a kept response is rendered again and compared, and a mismatch logged.
    # A finished private page from PageCache, or rendered and kept there. Runs after authentication
    # and the room check, before the page's own queries, as upstream Rails' cache_read_response
    # does. Pages with a flash, conditional requests, HEAD and responses that set a cookie or
    # aren't a 200 text/html page are rendered as usual and not kept. With CAMPFIRE_CHECK_CACHES=1
    # a hit is rendered again and compared.
    def cached_page
      cache = PageCache.instance
      return yield unless cache.enabled? && request.get? && @session && flash_now.empty? &&
        !env["HTTP_IF_NONE_MATCH"] && !env["HTTP_IF_MODIFIED_SINCE"]

      version = @page_cache_version
      gzip = env["HTTP_ACCEPT_ENCODING"].to_s.include?("gzip") # Compression's test
      key = JSON.generate([ request.path_info, request.query_string, base_url, request.user_agent, gzip,
        env["HTTP_ACCEPT"], env["HTTP_TURBO_FRAME"], current_user.id, request.cookies.except("_campfire_session").to_a.sort ])
      return yield if key.bytesize > PageCache::MAX_KEY_BYTES

      entry = cache.read(key, version, current_database_version)
      unless entry
        rendered = nil
        cache.synchronize_render(key, version) do
          entry = cache.read(key, version, current_database_version)
          if !entry && version == current_database_version
            cookies_before = response.headers["set-cookie"]
            rendered = yield
            entry = keep_page(cache, key, version, rendered, gzip) if response.headers["set-cookie"] == cookies_before
          end
        end
        return rendered if rendered && !entry
        return yield unless entry # waited behind a render made at a newer version: render this one alone
      end

      check_kept_page(entry, gzip) { yield } if CHECK_CACHES
      headers entry.headers
      headers "content-encoding" => "gzip" if gzip
      headers "content-length" => entry.body.bytesize.to_s
      entry.body
    end

    def current_database_version
      db.check_for_changes
      db.generation
    end

    def keep_page(cache, key, version, rendered, gzip)
      return unless status == 200 && response.headers["content-type"].to_s.start_with?("text/html") &&
        !response.headers["content-encoding"]
      html = rendered.is_a?(FragmentBody) ? rendered.to_s : Array(rendered).join
      return if html.empty?
      kept = PageCache::KEPT_HEADERS.filter_map { |name| (value = response.headers[name]) && [ name, value ] }.to_h
      kept["etag"] ||= %(W/"#{Digest::MD5.hexdigest(html)}") unless kept["last-modified"] # Rack::ETag's, once
      body = gzip ? (rendered.is_a?(FragmentBody) ? rendered.gzip : Compression.gzip_string(html)) : html
      cache.write(key, version, current_database_version, body, kept)
    end

    def check_kept_page(entry, gzip)
      fresh = yield
      fresh = fresh.is_a?(FragmentBody) ? fresh.to_s : Array(fresh).join
      kept = gzip ? Zlib.gunzip(entry.body) : entry.body
      warn "CACHE MISMATCH page #{request.path_info} (#{kept.bytesize} kept vs #{fresh.bytesize} fresh bytes)" unless fresh.b == kept.b
    end

    def check_kept(name, kept)
      fresh = yield
      fresh = fresh.to_s if fresh.is_a?(FragmentBody)
      warn "CACHE MISMATCH #{name} #{request.path_info} (#{kept.bytesize} kept vs #{fresh.bytesize} fresh bytes)" unless fresh.b == kept.b
    end

    # Rails' redirect_to: always 302.
    def redirect(uri, *args)
      status 302
      response["Location"] = uri
      headers "Content-Type" => "text/html; charset=utf-8"
      response.headers["Cache-Control"] ||= "no-cache"
      halt(*args)
    end

    TRUSTED_PROXIES = %w[ 127.0.0.0/8 ::1/128 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 ].map { IPAddr.new(it) }.freeze

    # ActionDispatch::RemoteIp: the client is the last X-Forwarded-For address that isn't a trusted
    # proxy, when the request came through one.
    def remote_ip
      @remote_ip ||= begin
        normalize = ->(ip) { header_text(ip).strip.delete_prefix("::ffff:") }
        trusted = ->(ip) { (addr = IPAddr.new(ip) rescue nil) && TRUSTED_PROXIES.any? { it.include?(addr) } }
        remote = normalize.(request.env["REMOTE_ADDR"])
        forwarded = request.env["HTTP_X_FORWARDED_FOR"].to_s.split(",").map(&normalize).reject(&:empty?).reverse
        if !forwarded.empty? && trusted.(remote)
          forwarded.find { !trusted.(it) } || forwarded.last
        else
          remote
        end
      end
    end

    def current_user = @current_user

    # Header values arrive as binary strings, which sqlite3 binds as BLOBs that never equal TEXT.
    def header_text(value) = value.to_s.dup.force_encoding(Encoding::UTF_8)
    def base_url = (@base_url ||= "#{request.scheme}://#{request.host_with_port}")
    def url_for(path) = "#{base_url}#{path}"

    def build_view(**locals)
      view = View.new(app: runtime, current_user: current_user, base_url: base_url, user_agent: request.user_agent, flash: flash_now)
        .with(referrer: request.referer, request_url: request.url, **locals)
      if @collect_fragments && !@fragment_view
        @fragment_view = view
        view.collecting_fragments { }
      end
      view
    end

    def html_headers(type = "text/html")
      headers "Cache-Control" => "max-age=0, private, must-revalidate", "Content-Type" => "#{type}; charset=utf-8"
      headers "Vary" => "Accept" if vary_by_accept?
    end

    # ActionDispatch::Request#should_apply_vary_header?: only when the format came from a
    # non-browser Accept header.
    def vary_by_accept?
      accept = request.env["HTTP_ACCEPT"].to_s
      params["format"].to_s.empty? && !accept.empty? && !accept.match?(/,\s*\*\/\*|\*\/\*\s*,/)
    end

    def without_version_headers
      response.headers.delete("X-Version")
      response.headers.delete("X-Rev")
    end

    # Avatars and the account logo go out without ActionDispatch's default headers, as Rails sends them.
    def without_security_headers
      SECURITY_HEADERS.each_key { response.headers.delete(it) }
    end

    # send_file as ActionController::DataStreaming writes it.
    def send_inline_file(path, type)
      without_security_headers
      headers "Content-Type" => type, "Content-Transfer-Encoding" => "binary",
        "Content-Disposition" => Storage.content_disposition("inline", File.basename(path))
      File.binread(path)
    end

    # The ETag of a page built from cached message fragments: everything it's rendered from.
    def page_etag(*parts)
      headers "ETag" => %(W/"#{Digest::MD5.hexdigest([ base_url, request.user_agent, current_user&.id, current_user&.updated_at, current_user&.role, *parts ].join("|"))}")
    end

    # frame_layout: false for MessagesController, whose `layout false, only: :index` replaces
    # turbo-rails' frame layout, so its other actions render the application layout for frames too.
    def render_layout(view, main:, page_title: nil, body_class: nil, head: nil, nav: nil, footer: nil, sidebar: nil, frame_layout: true)
      html_headers
      # Turbo::Frames::FrameRequest: frame requests get turbo-rails' bare frame layout.
      if frame_layout && request.env["HTTP_TURBO_FRAME"].to_s != ""
        return "<html>\n  <head>\n    \n    #{head}\n  </head>\n  <body>\n    #{main}\n  </body>\n</html>\n"
      end

      view.with(page_title: page_title, body_class: body_class, content_head: head, content_nav: nav, content_main: main,
        content_footer: footer, content_sidebar: sidebar)
      headers "Link" => Assets.link_header
      view.tpl_layouts_application
    end

    def render_page(template, page_title: nil, head: nil, body_class: nil, **locals)
      view = build_view(**locals)
      render_layout(view, main: view.public_send(:"tpl_#{template}"), page_title: page_title, head: head, body_class: body_class)
    end

    def flash_now
      @flash ||= read_flash
    end

    def render_sign_in_rejection(code)
      flash_now["alert"] = "Too many requests or unauthorized."
      status code
      render_page(:sessions_new, page_title: "Sign in", head: %(<meta name="turbo-visit-control" content="reload">), email_address: params["email_address"])
    end

    def render_incompatible_browser
      view = build_view
      render_layout(view, main: view.tpl_sessions_incompatible_browser,
        page_title: Platform.new(request.user_agent).apple_messages? ? "Campfire" : "Unsupported browser")
    end

    def signed_blob!(signed_id)
      id = Storage.find_signed_blob_id(runtime, signed_id) or active_storage_not_found
      row = db.row("SELECT #{Blob.columns} FROM active_storage_blobs WHERE id = ?", id) or active_storage_not_found
      Blob.new(*row)
    end

    # ActionController::Head#head: no body, no-cache. Rails sets the controller's formats only after
    # the before-actions, so a head from one is text/html; inside an action it's the request's format.
    def head_response(code, in_action: false)
      turbo = in_action && request.env["HTTP_ACCEPT"].to_s.start_with?("text/vnd.turbo-stream.html")
      halt code, { "Content-Type" => turbo ? "text/vnd.turbo-stream.html" : "text/html", "Cache-Control" => "no-cache" }, ""
    end

    # ActiveRecord::RecordNotFound from a find: the public 404 page, as ActionDispatch::ShowExceptions
    # serves it (none of the controller's headers).

    def record_not_found!
      without_security_headers
      without_version_headers
      halt 404, { "Content-Type" => "text/html; charset=UTF-8" }, File.read(File.join(ROOT, "public/404.html"))
    end

    # Active Storage's controllers aren't ApplicationControllers: a missing blob is the public 404
    # page, without version headers.
    def active_storage_not_found
      without_version_headers
      halt 404, { "Content-Type" => "text/html", "Cache-Control" => "no-cache" }, File.read(File.join(ROOT, "public/404.html"))
    end

    # ActiveStorage::Blobs::RedirectController and Representations::RedirectController
    # Blob#url: the type and disposition the blob is served with, not the uploader's.
    def redirect_to_disk(blob, disposition)
      without_version_headers
      disposition = Storage.forced_disposition_for_serving(blob.content_type) || (disposition == "attachment" ? "attachment" : "inline")
      headers "Cache-Control" => "max-age=300, private"
      redirect url_for(Storage.disk_path(runtime, key: blob.key, filename: blob.filename,
        content_type: Storage.content_type_for_serving(blob.content_type),
        disposition: Storage.content_disposition(disposition, blob.filename)))
    end

    # ---- Authentication

    def restore_authentication
      return @current_user if defined?(@current_user) && @current_user
      raw = request.cookies["session_token"] or return nil
      token = secrets.verify_cookie("session_token", raw) or return nil
      session = repo.session_by_token(token) or return nil
      user = repo.user(session.user_id) or return nil
      resume_session(session)
      @session = session
      @current_user = user
    end

    def require_authentication!
      if restore_authentication
        browser_gate! if request.get? || request.head? # writes pass the gate after the forgery check
        return
      end

      write_session("return_to_after_authenticating" => request.url)
      halt redirect(url_for("/session/new"))
    end

    def resume_session(session)
      if TimeFormat.parse(session.last_active_at) < Time.now - SESSION_REFRESH
        now = TimeFormat.now_text
        db.transaction do |w|
          w.run("UPDATE sessions SET user_agent = ?, ip_address = ?, last_active_at = ?, updated_at = ? WHERE id = ?",
            header_text(request.user_agent), remote_ip, now, now, session.id)
        end
        set_session_cookie(session.token)
      end
    end

    def start_new_session_for(user)
      token = Tokens.base58(24)
      now = TimeFormat.now_text
      db.transaction do |w|
        w.run("INSERT INTO sessions (created_at, ip_address, last_active_at, token, updated_at, user_agent, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
          now, remote_ip, now, token, now, header_text(request.user_agent), user.id)
      end
      set_session_cookie(token)
      @current_user = user
    end

    def set_session_cookie(token)
      expires = permanent_expiry
      response.set_cookie("session_token", value: secrets.sign_cookie("session_token", token, expires), path: "/",
        expires: expires, httponly: true, same_site: :lax)
    end

    def permanent_expiry
      now = Time.now.utc
      Time.utc(now.year + PERMANENT_YEARS, now.month, now.day, now.hour, now.min, now.sec, now.usec)
    end

    def redirect_after_authentication
      session = read_session
      target = session.delete("return_to_after_authenticating")
      write_session(session) if target
      redirect target || url_for("/")
    end

    # ---- The Rails session cookie, used here only for flash and the post-login redirect.

    def read_session
      raw = request.cookies["_campfire_session"]
      (raw && secrets.decrypt_cookie("_campfire_session", raw)) || {}
    end

    def write_session(hash)
      if hash.empty?
        response.delete_cookie("_campfire_session", path: "/")
      else
        expires = Time.now.utc + PERMANENT_YEARS * 365.25 * 86_400
        response.set_cookie("_campfire_session", value: secrets.encrypt_cookie("_campfire_session", hash, expires), path: "/",
          expires: expires, httponly: true, same_site: :lax)
      end
    end

    def read_flash
      return {} unless request.cookies["_campfire_session"]
      session = read_session
      flash = session.delete("flash")
      return {} unless flash
      write_session(session)
      (flash["flashes"] || {}).reject { |key, _| Array(flash["discard"]).include?(key) }
    end

    def redirect_with_alert(path, alert) = redirect_with_flash(path, "alert", alert)
    def redirect_with_notice(path, notice) = redirect_with_flash(path, "notice", notice)

    def redirect_with_flash(path, key, message)
      session = read_session
      session["flash"] = { "discard" => [], "flashes" => { key => message } }
      write_session(session)
      redirect url_for(path)
    end

    # Sec-Fetch-Site replaces CSRF tokens, as in the Rust port: cross-site writes are rejected,
    # and so is a mismatched Origin.
    # verify_authenticity_token by Sec-Fetch-Site instead of tokens, as the Rust port does
    # (crates/kit/src/ctx.rs; Rails main's `protect_from_forgery using: :header_only`): a null or
    # foreign Origin fails, same-origin and same-site pass, and a missing header passes only when
    # neither the request nor the app uses SSL. A failure is InvalidAuthenticityToken's public 422.
    def verify_same_origin!
      return if request.get? || request.head?
      origin = request.env["HTTP_ORIGIN"]
      valid_origin = origin.nil? || (origin != "null" && origin == base_url)
      allowed =
        case request.env["HTTP_SEC_FETCH_SITE"]
        when "same-origin", "same-site" then true
        when nil then !request.ssl? && !Campfire.ssl?
        else false
        end
      unprocessable_entity! unless valid_origin && allowed
      browser_gate!
    end

    # AllowBrowser's allow_browser: the last of ApplicationController's before-actions, after the
    # ban check, authentication and forgery protection, so a signed-out old browser is still sent
    # to sign in first.
    def browser_gate!
      halt render_incompatible_browser if Browsers.blocked?(request.user_agent)
    end

    # InvalidAuthenticityToken or RecordInvalid: the public 422 page, as ActionDispatch::ShowExceptions
    # serves it (none of the controller's headers).
    def unprocessable_entity!
      without_security_headers
      without_version_headers
      halt 422, { "Content-Type" => "text/html; charset=utf-8" }, File.read(File.join(ROOT, "public/422.html"))
    end

    # ---- Rooms

    # Authentication's restore_authentication || bot_authentication, then the user's room. Forgery
    # protection applies unless the request was authenticated by its bot key
    # (`protect_from_forgery ... unless: -> { authenticated_by.bot_key? }`).
    def bot_room!(bot_key, room_id)
      bot = restore_authentication
      if bot
        verify_same_origin!
      else
        id, token = bot_key.strip.split("-", 2)
        row = db.row("SELECT #{User.columns} FROM users WHERE id = ? AND bot_token = ? AND status = 0 AND role = 2 LIMIT 1", id.to_i, token.to_s)
        unless row
          write_session("return_to_after_authenticating" => request.url)
          halt redirect(url_for("/session/new"))
        end
        bot = User.new(*row)
      end
      browser_gate!
      room = repo.user_room(bot.id, room_id.to_i) or head_response(404)
      [ bot, room ]
    end

    def active_bot!(id)
      row = db.row("SELECT #{User.columns} FROM users WHERE id = ? AND status = 0 AND role = 2", id.to_i) or record_not_found!
      User.new(*row)
    end

    def can_create_rooms?
      current_user.administrator? || !runtime.account.restrict_room_creation_to_administrators?
    end

    def render_room_settings(form_type, room)
      users = repo.active_users_ordered
      editing = !room.nil?
      administer = editing ? current_user.can_administer?(room) : true
      if form_type == "closed"
        member_ids = editing ? repo.room_user_ids(room.id) : []
        selected, unselected = users.partition { member_ids.include?(it.id) }
      else
        selected, unselected = [], users
      end
      type_change_path = editing ? "/rooms/#{form_type == "open" ? "closeds" : "opens"}/#{room.id}/edit" : "/rooms/#{form_type == "open" ? "closeds" : "opens"}/new"
      view = build_view(room: room, editing: editing, form_type: form_type, can_administer: administer,
        room_name: editing ? room.name : "New room", type_change_path: type_change_path, user_count: users.size,
        selected_users: selected, unselected_users: unselected, last_room_visited: last_room_visited)
      render_layout(view, page_title: editing ? "Edit settings for #{room.name}" : "New chat room",
        nav: view.tpl_rooms_settings_nav, main: view.tpl_rooms_settings)
    end

    def reachable_message!(id)
      row = db.row(<<~SQL, current_user.id, id.to_i) or record_not_found!
        SELECT #{Message.columns} FROM messages INNER JOIN rooms ON messages.room_id = rooms.id
        INNER JOIN memberships ON rooms.id = memberships.room_id WHERE memberships.user_id = ? AND messages.id = ? LIMIT 1
      SQL
      Message.new(*row)
    end

    def room_scoped!(room_id)
      membership = repo.membership(current_user.id, room_id.to_i) or record_not_found!
      repo.room(membership.room_id)
    end

    def remember_last_room_visited(room)
      if request.cookies["last_room"] != room.id.to_s
        response.set_cookie("last_room", value: room.id.to_s, path: "/", expires: permanent_expiry, same_site: :lax)
      end
    end

    def last_room_visited
      (id = request.cookies["last_room"]) && repo.user_room(current_user.id, id.to_i) || repo.user_original_room(current_user.id)
    end

    def find_room_messages(room, message_id)
      if message_id && (anchor = repo.room_message(room.id, message_id.to_i))
        repo.page_before(room.id, anchor.created_at) + [ anchor ] + repo.page_after(room.id, anchor.created_at)
      else
        repo.last_page(room.id)
      end
    end

    def render_room(room, messages)
      invitation = room.id == repo.original_room_id && repo.room_message_count(room.id) <= Repo::PAGE_SIZE
      account = runtime.account
      direct_names = (repo.direct_room_member_names(room.id, current_user.id) if room.direct?)
      page_etag("room", room, account.updated_at, account.name, invitation, message_versions(messages), direct_names, flash_now)
      shell_page([ "room", room, direct_names, invitation ], messages) { render_room_page(room, messages, invitation) }
    end

    # Room and search pages, assembled on every request as the Elixir port's room_page.ex and
    # searches.ex do: the shell around the messages is kept by everything its templates read
    # except the messages (the user, the account, the request's host, user agent, frame and flash,
    # and the page's own inputs), and each request splices in the messages' cached fragments,
    # whose compressed blocks are kept too. With CAMPFIRE_CHECK_CACHES=1 a page built from a kept
    # shell is rendered in full as well and compared.
    SHELLS = {}
    SHELLS_LIMIT = 512
    KEPT_HEADERS = %w[ cache-control content-type vary link last-modified ].freeze
    Shell = Data.define(:parts, :headers)

    def shell_page(inputs, messages, &render)
      key = [ *inputs, current_user, runtime.account, runtime.account_logo_attached?, base_url, request.user_agent,
        flash_now, env["HTTP_TURBO_FRAME"], env["HTTP_ACCEPT"], messages.size ]
      if Campfire.rust_caching_only?
        body = fragment_page(&render)
        body = FragmentBody.new(body) unless body.is_a?(FragmentBody)
      elsif (shell = SHELLS.delete(key))
        SHELLS[key] = shell
        headers shell.headers
        fragments = message_fragments(messages)
        body = FragmentBody.new(shell.parts.map { it.is_a?(Integer) ? fragments[it] : it })
        check_kept("page", body.to_s) { fragment_page(&render) } if CHECK_CACHES
      else
        body = fragment_page(&render)
        body = FragmentBody.new(body) unless body.is_a?(FragmentBody)
        slot = -1
        parts = body.parts.map { it.is_a?(Fragment) ? (slot += 1) : it.freeze }
        kept_headers = KEPT_HEADERS.filter_map { |name| (value = response.headers[name]) && [ name, value ] }.to_h
        SHELLS[key] = Shell.new(parts.freeze, kept_headers.freeze)
        SHELLS.delete(SHELLS.first[0]) while SHELLS.size > SHELLS_LIMIT
      end
      headers "Content-Length" => body.bytesize.to_s
      body
    end

    # The cached fragment of each message, in order, rendering the ones not cached yet.
    def message_fragments(messages)
      view = build_view
      message_views(messages).map { view.message_fragment(it) }
    end

    # MessagesController#index: the page's parts, and so their gzip, kept by its ETag (which covers
    # every message's version) and host, as the Elixir port's messages.ex does.
    MESSAGES_PAGES = {}
    MESSAGES_PAGES_LIMIT = 512

    def messages_page(messages)
      key = [ response.headers["etag"], base_url ]
      if Campfire.rust_caching_only?
        page = messages_html(messages)
        page = FragmentBody.new(page) unless page.is_a?(FragmentBody)
      elsif (page = MESSAGES_PAGES.delete(key))
        MESSAGES_PAGES[key] = page
        check_kept("messages", page.to_s) { messages_html(messages) } if CHECK_CACHES
      else
        page = messages_html(messages)
        page = FragmentBody.new(page) unless page.is_a?(FragmentBody)
        MESSAGES_PAGES[key] = page
        MESSAGES_PAGES.delete(MESSAGES_PAGES.first[0]) while MESSAGES_PAGES.size > MESSAGES_PAGES_LIMIT
      end
      headers "Content-Length" => page.bytesize.to_s
      page
    end

    # A page whose message fragments go out as a FragmentBody (cached gzip blocks).
    def fragment_page
      @collect_fragments = true
      html = yield
      view = @fragment_view
      body = view&.fragments ? FragmentBody.from(html, view.fragments) : [ html ]
      headers "Content-Length" => body.is_a?(FragmentBody) ? body.bytesize.to_s : html.bytesize.to_s
      body
    ensure
      @collect_fragments = false
    end

    def render_room_page(room, messages, invitation)
      views = message_views(messages)
      view = build_view(room: room, messages: views, invitation: invitation)
      render_layout(view,
        page_title: view.room_display_name(room), body_class: "sidebar",
        head: view.tpl_rooms_head, nav: view.tpl_rooms_nav, main: view.tpl_rooms_show, footer: view.tpl_rooms_composer,
        sidebar: sidebar_frame_tag)
    end

    def render_welcome
      view = build_view
      main = <<~HTML
        <div id="message-area" class="message-area">
          <div class="message-area--empty min-width center">
            <figure class="center pad">
              #{view.image_tag("messages-empty.svg", aria: { hidden: "true" }, class: "colorize--black translucent")}
              <span class="for-screen-reader">#{HTML.h(current_user.name)}</span>
            </figure>
          </div>
        </div>
      HTML
      render_layout(view, main: main, page_title: "No rooms yet", body_class: "sidebar", sidebar: sidebar_frame_tag)
    end

    def sidebar_frame_tag
      %(<turbo-frame data-turbo-permanent="true" data-controller="rooms-list read-rooms turbo-frame" data-rooms-list-unread-class="unread" data-action="presence:present@window->rooms-list#read read-rooms:read->rooms-list#read turbo:frame-load->rooms-list#loaded refresh-room:visible@window->turbo-frame#reload" id="user_sidebar" src="/users/me/sidebar" target="_top"></turbo-frame>)
    end

    # MessagesController#create's `render action: :room_not_found`: the HTML template in the
    # application layout, whose composer frame the submitting frame takes.
    def render_room_not_found
      view = build_view
      render_layout(view, main: view.tpl_messages_room_not_found, frame_layout: false)
    end

    def messages_html(messages)
      fragment_page do
        view = build_view
        message_views(messages).map { view.render_message_cached(it) }.join
      end
    end

    # Each message's id and version, as the page ETags list them.
    def message_versions(messages)
      messages.map { "#{it.id}-#{it.updated_at}" }.join("|")
    end

    # ActionController::ConditionalGet#fresh_when(@messages): the collection's cache key.
    def etag_for_messages(messages)
      page_etag("messages", message_versions(messages))
    end

    # The data each message partial needs, loaded only for messages not already in the fragment
    # cache (as Rails' collection caching does).
    def message_views(messages)
      Messages.views(self, messages)
    end

    # ---- Sidebar

    def render_sidebar
      memberships = repo.sidebar_memberships(current_user.id)
      directs, others = memberships.partition { |_, room| room.direct? }
      directs = directs.sort_by { |_, room| room.updated_at }.reverse

      exclude = repo.member_ids_of_rooms(repo.direct_room_ids(current_user.id)).uniq + [ current_user.id ]
      placeholders = repo.active_users_excluding(exclude, [ 20 - exclude.size, 0 ].max)

      view = build_view(other_memberships: others, placeholder_users: placeholders)
      view = view.with(direct_memberships: cached_sidebar_directs(view, directs))
      render_layout(view, main: view.tpl_users_sidebar)
    end

    # `render partial: "users/sidebars/rooms/direct", collection: ..., cached: true`: the Redis cache
    # store, keyed by the membership's id and updated_at. PresenceChannel marks a room read with
    # update_all, which leaves updated_at alone, so a room read since its fragment was cached still
    # shows unread here until a broadcast updates it.
    def cached_sidebar_directs(view, directs)
      return [] if directs.empty?
      keys = directs.map { |membership, _| "views/users/sidebars/rooms/_direct/memberships/#{membership.id}-#{membership.updated_at}" }
      cached = Broadcasts.redis_call("MGET", *keys)
      directs.each_with_index.map do |(membership, room), index|
        next cached[index].force_encoding(Encoding::UTF_8) if cached[index]
        members = repo.room_users_except(room.id, current_user.id)
        members = [ current_user ] if members.empty?
        view.render_sidebar_direct(membership, room, members).tap { Broadcasts.redis_call("SET", keys[index], it) }
      end
    end

    # ---- Searches

    def render_search(query, raw_query, messages)
      recent = repo.recent_search_queries(current_user.id)
      return_to_room = last_room_visited
      account = runtime.account
      page_etag("search", raw_query, account.updated_at, recent, return_to_room.id, message_versions(messages))
      shell_page([ "search", query, raw_query, recent, return_to_room ], messages) do
        render_search_page(query, raw_query, messages, recent, return_to_room)
      end
    end

    def render_search_page(query, raw_query, messages, recent, return_to_room)
      views = message_views(messages)
      view = build_view(query: query, raw_query: raw_query, count: messages.size, messages: views, recent_searches: recent,
        return_to_room: return_to_room)
      view.with(recents: view.tpl_searches_recents)
      render_layout(view, page_title: "Search", body_class: "sidebar searches",
        nav: view.tpl_searches_nav, main: view.tpl_searches_index, footer: view.tpl_searches_footer, sidebar: view.tpl_searches_sidebar)
    end

  end
end
