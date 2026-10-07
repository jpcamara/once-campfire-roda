require "sequel"

module Campfire
  # Sequel over SQLite. Each DB (the process's, and one per job thread) is its own single-threaded
  # Sequel database with two shards, :read_only for reads and :default for writes, so it holds
  # exactly two connections. A read runs to completion without yielding to the fiber scheduler, so
  # fibers never see each other's half-finished statements. Writes take a fiber-aware lock and
  # BEGIN IMMEDIATE; the writer waits for other processes with the sqlite3 gem's busy handler,
  # which sleeps (and so lets other fibers run, on the reader connection).
  #
  # Every query is a Sequel prepared statement, prepared once per connection and run by name.
  # Sequel's type conversion is off: values come back as SQLite stores them (Rails' text timestamps
  # among them), and the app parses them where it needs to.
  class DB
    BUSY_TIMEOUT_MS = 5_000

    def self.path
      ENV.fetch("DATABASE_PATH") { File.join(ENV.fetch("STORAGE_PATH", "storage"), "db", "production.sqlite3") }
    end

    # `IN (?, ?, ...)` for a list of ids; each list length is its own prepared statement.
    def self.in_list(count)
      Array.new(count, "?").join(", ")
    end

    def self.connect(path)
      # SQLite's own LIKE (case-insensitive for ASCII), as Rails leaves it; Sequel turns it case-sensitive.
      sequel = Sequel.sqlite(path, servers: { read_only: {} }, single_threaded: true, keep_reference: false,
        timeout: BUSY_TIMEOUT_MS, case_sensitive_like: false, after_connect: ->(connection, server) { configure(connection, server) })
      sequel.conversion_procs.clear
      sequel
    end

    def self.configure(connection, server)
      # The sqlite3 gem's own busy handling: the writer waits with busy_handler_timeout=, which
      # sleeps between tries (and so lets this process's other fibers run); the reader keeps the
      # plain busy_timeout Sequel sets from `timeout:`.
      connection.busy_handler_timeout = BUSY_TIMEOUT_MS if server == :default
      connection.execute("PRAGMA journal_mode = WAL")
      connection.execute("PRAGMA synchronous = NORMAL")
      connection.execute("PRAGMA foreign_keys = ON")
      connection.execute("PRAGMA mmap_size = 0")
      # Rails' journal_size_limit and cache_size; checkpoints are bin/checkpoint's.
      connection.execute("PRAGMA journal_size_limit = 67108864")
      connection.execute("PRAGMA cache_size = 2000")
      connection.execute("PRAGMA wal_autocheckpoint = 0")
    end

    # Prepared statements by shard and SQL, registered with Sequel once and named in the order they're
    # first used.
    class Statements
      def initialize(sequel)
        @sequel = sequel
        @names = {}
      end

      def fetch(server, sql, arity)
        @names[[ server, sql, arity ]] ||= :"q#{@names.size}".tap do |name|
          binds = Array.new(arity) { :"$a#{it}" }
          @sequel.dataset.with_sql(sql, *binds).server(server).prepare(:select, name)
        end
      end
    end

    # Queries on one shard. Rows come back as arrays, in the order of the SELECT's columns.
    #
    # A statement runs through Sequel::Database#execute by its prepared statement's name: Sequel's
    # pool, cached SQLite statement and error handling, without binding through a cloned dataset or
    # building a hash per row.
    class Connection
      ARGUMENT_KEYS = Array.new(256) { "a#{it}".freeze }.freeze # more for longer IN lists, made as needed

      def initialize(sequel, statements, server)
        @sequel, @statements, @server = sequel, statements, server
      end

      def rows(sql, *binds)
        rows = nil
        @sequel.execute(@statements.fetch(@server, sql, binds.size), server: @server, arguments: arguments(binds)) { rows = it.to_a }
        rows
      end

      def row(sql, *binds) = rows(sql, *binds).first
      def value(sql, *binds) = row(sql, *binds)&.first

      # The number of rows changed.
      def run(sql, *binds)
        @sequel.execute_dui(@statements.fetch(@server, sql, binds.size), server: @server, arguments: arguments(binds))
      end

      def last_insert_row_id
        @sequel.synchronize(@server) { it.last_insert_row_id }
      end

      private
        # Header values can arrive binary-encoded, and SQLite binds those as BLOBs, which never
        # equal TEXT. Everything the app binds is text.
        def arguments(binds)
          arguments = {}
          binds.each_with_index do |value, i|
            value = value.dup.force_encoding(Encoding::UTF_8) if value.is_a?(String) && value.encoding == Encoding::BINARY
            arguments[ARGUMENT_KEYS[i] || "a#{i}"] = value
          end
          arguments
        end
    end

    # Read results, kept until the database changes. PRAGMA data_version on the reader connection
    # changes whenever another connection commits: this process's writer, or another worker's. It's
    # read again at the start of each request, cable command and job (DB#check_for_changes), and the
    # cache is also cleared after this process's own commits. Rows are frozen, as they're shared.
    # `generation` counts the clears: anything kept by it lasts as long as the reads it was made from.
    class ReadCache
      LIMIT = 8192

      attr_reader :generation

      def initialize(sequel)
        @sequel = sequel
        @entries = {}
        @version = nil
        @generation = 0
      end

      def fetch(key)
        return yield if Campfire.rust_caching_only?
        if (rows = @entries.delete(key))
          @entries[key] = rows
        else
          rows = @entries[key] = yield
          @entries.delete(@entries.first[0]) while @entries.size > LIMIT
          rows
        end
      end

      def check_for_changes
        version = @sequel.synchronize(:read_only) { it.get_first_value("PRAGMA data_version") }
        clear unless version == @version
        @version = version
      end

      def clear
        @entries.clear
        @generation += 1
      end
    end

    def initialize(path = self.class.path)
      @sequel = self.class.connect(path)
      statements = Statements.new(@sequel)
      @reader = Connection.new(@sequel, statements, :read_only)
      @writer = Connection.new(@sequel, statements, :default)
      @write_lock = Mutex.new
      @cache = ReadCache.new(@sequel)
    end

    def rows(sql, *binds) = @cache.fetch([ :rows, sql, *binds ]) { @reader.rows(sql, *binds).each(&:freeze).freeze }
    def row(sql, *binds) = @cache.fetch([ :row, sql, *binds ]) { @reader.row(sql, *binds)&.freeze }
    def value(sql, *binds) = row(sql, *binds)&.first

    def check_for_changes = @cache.check_for_changes
    def generation = @cache.generation

    def transaction
      @write_lock.synchronize do
        @sequel.transaction(server: :default, mode: :immediate) { yield @writer }
      ensure
        @cache.clear
      end
    end
  end
end
