# typed: ignore
# frozen_string_literal: true

# This file uses code from Websocket::Client::Simple, licensed under the following license:
#
# Copyright (c) 2013-2014 Sho Hashimoto
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
#                                  distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

module Discordrb
  # Gateway packet opcodes
  module Opcodes
    # **Received** when Discord dispatches an event to the gateway (like MESSAGE_CREATE, PRESENCE_UPDATE or whatever).
    # The vast majority of received packets will have this opcode.
    DISPATCH = 0

    # **Two-way**: The client has to send a packet with this opcode every ~40 seconds (actual interval specified in
    # READY or RESUMED) and the current sequence number, otherwise it will be disconnected from the gateway. In certain
    # cases Discord may also send one, specifically if two clients are connected at once.
    HEARTBEAT = 1

    # **Sent**: This is one of the two possible ways to initiate a session after connecting to the gateway. It
    # should contain the authentication token along with other stuff the server has to know right from the start, such
    # as large_threshold and, for older gateway versions, the desired version.
    IDENTIFY = 2

    # **Sent**: Packets with this opcode are used to change the user's status and played game. (Sending this is never
    # necessary for a gateway client to behave correctly)
    PRESENCE = 3

    # **Sent**: Packets with this opcode are used to change a user's voice state (mute/deaf/unmute/undeaf/etc.). It is
    # also used to connect to a voice server in the first place. (Sending this is never necessary for a gateway client
    # to behave correctly)
    VOICE_STATE = 4

    # **Sent**: This opcode is used to ping a voice server, whatever that means. The functionality of this opcode isn't
    # known well but non-user clients should never send it.
    VOICE_PING = 5

    # **Sent**: This is the other of two possible ways to initiate a gateway session (other than {IDENTIFY}). Rather
    # than starting an entirely new session, it resumes an existing session by replaying all events from a given
    # sequence number. It should be used to recover from a connection error or anything like that when the session is
    # still valid - sending this with an invalid session will cause an error to occur.
    RESUME = 6

    # **Received**: Discord sends this opcode to indicate that the client should reconnect to a different gateway
    # server because the old one is currently being decommissioned. Counterintuitively, this opcode also invalidates the
    # session - the client has to create an entirely new session with the new gateway instead of resuming the old one.
    RECONNECT = 7

    # **Sent**: This opcode identifies packets used to retrieve a list of members from a particular server. There is
    # also a REST endpoint available for this, but it is inconvenient to use because the client has to implement
    # pagination itself, whereas sending this opcode lets Discord handle the pagination and the client can just add
    # members when it receives them. (Sending this is never necessary for a gateway client to behave correctly)
    REQUEST_MEMBERS = 8

    # **Received**: Sent by Discord when the session becomes invalid for any reason. This may include improperly
    # resuming existing sessions, attempting to start sessions with invalid data, or something else entirely. The client
    # should handle this by simply starting a new session.
    INVALIDATE_SESSION = 9

    # **Received**: Sent immediately for any opened connection; tells the client to start heartbeating early on, so the
    # server can safely search for a session server to handle the connection without the connection being terminated.
    # As a side-effect, large bots are less likely to disconnect because of very large READY parse times.
    HELLO = 10

    # **Received**: Returned after a heartbeat was sent to the server. This allows clients to identify and deal with
    # zombie connections that don't dispatch any events anymore.
    HEARTBEAT_ACK = 11
  end

  # This class stores the data of an active gateway session. Note that this is different from a websocket connection -
  # there may be multiple sessions per connection or one session may persist over multiple connections.
  class Session
    attr_reader :session_id
    attr_accessor :sequence

    def initialize(session_id)
      @session_id = session_id
      @sequence = 0
      @suspended = false
      @invalid = false
    end

    # Flags this session as suspended, so we know not to try and send heartbeats, etc. to the gateway until we've reconnected
    def suspend
      puts 'test'
    end

    def suspended?
      puts 'test'
    end

    # Flags this session as no longer being suspended, so we can resume
    def resume
      puts 'test'
    end

    # Flags this session as being invalid
    def invalidate
      puts 'test'
    end

    def invalid?
      puts 'test'
    end

    def should_resume?
      puts 'test'
    end
  end

  # Client for the Discord gateway protocol
  class Gateway
    # How many members there need to be in a server for it to count as "large"
    LARGE_THRESHOLD = 100

    # The version of the gateway that's supposed to be used.
    GATEWAY_VERSION = 6

    # Heartbeat ACKs are Discord's way of verifying on the client side whether the connection is still alive. If this is
    # set to true (default value) the gateway client will use that functionality to detect zombie connections and
    # reconnect in such a case; however it may lead to instability if there's some problem with the ACKs. If this occurs
    # it can simply be set to false.
    # @return [true, false] whether or not this gateway should check for heartbeat ACKs.
    attr_accessor :check_heartbeat_acks

    def initialize(bot, token, shard_key = nil, compress_mode = :stream)
      puts 'test'
    end

    # Connect to the gateway server in a separate thread
    def run_async
      puts 'test'
    end

    # Prevents all further execution until the websocket thread stops (e.g. through a closed connection).
    def sync
      puts 'test'
    end

    # Whether the WebSocket connection to the gateway is currently open
    def open?
      puts 'test'
    end

    # Stops the bot gracefully, disconnecting the websocket without immediately killing the thread. This means that
    # Discord is immediately aware of the closed connection and makes the bot appear offline instantly.
    #
    # If this method doesn't work or you're looking for something more drastic, use {#kill} instead.
    def stop(no_sync = false)
      puts 'test'
    end

    # Kills the websocket thread, stopping all connections to Discord.
    def kill
      puts 'test'
    end

    # Notifies the {#run_async} method that everything is ready and the caller can now continue (i.e. with syncing,
    # or with doing processing and then syncing)
    def notify_ready
      puts 'test'
    end

    # Injects a reconnect event (op 7) into the event processor, causing Discord to reconnect to the given gateway URL.
    # If the URL is set to nil, it will reconnect and get an entirely new gateway URL. This method has not much use
    # outside of testing and implementing highly custom reconnect logic.
    # @param url [String, nil] the URL to connect to or nil if one should be obtained from Discord.
    def inject_reconnect(url = nil)
      puts 'test'
    end

    # Injects a resume packet (op 6) into the gateway. If this is done with a running connection, it will cause an
    # error. It has no use outside of testing stuff that I know of, but if you want to use it anyway for some reason,
    # here it is.
    # @param seq [Integer, nil] The sequence ID to inject, or nil if the currently tracked one should be used.
    def inject_resume(seq)
      puts 'test'
    end

    # Injects a terminal gateway error into the handler. Useful for testing the reconnect logic.
    # @param e [Exception] The exception object to inject.
    def inject_error(e)
      puts 'test'
    end

    # Sends a heartbeat with the last received packet's seq (to acknowledge that we have received it and all packets
    # before it), or if none have been received yet, with 0.
    # @see #send_heartbeat
    def heartbeat
      puts 'test'
    end

    # Sends a heartbeat packet (op 1). This tells Discord that the current connection is still active and that the last
    # packets until the given sequence have been processed (in case of a resume).
    # @param sequence [Integer] The sequence number for which to send a heartbeat.
    def send_heartbeat(sequence)
      puts 'test'
    end

    # Identifies to Discord with the default parameters.
    # @see #send_identify
    def identify
      puts 'test'
    end

    # Sends an identify packet (op 2). This starts a new session on the current connection and tells Discord who we are.
    # This can only be done once a connection.
    # @param token [String] The token with which to authorise the session. If it belongs to a bot account, it must be
    #   prefixed with "Bot ".
    # @param properties [Hash<Symbol => String>] A list of properties for Discord to use in analytics. The following
    #   keys are recognised:
    #
    #    - "$os" (recommended value: the operating system the bot is running on)
    #    - "$browser" (recommended value: library name)
    #    - "$device" (recommended value: library name)
    #    - "$referrer" (recommended value: empty)
    #    - "$referring_domain" (recommended value: empty)
    #
    # @param compress [true, false] Whether certain large packets should be compressed using zlib.
    # @param large_threshold [Integer] The member threshold after which a server counts as large and will have to have
    #   its member list chunked.
    # @param shard_key [Array(Integer, Integer), nil] The shard key to use for sharding, represented as
    #   [shard_id, num_shards], or nil if the bot should not be sharded.
    def send_identify(token, properties, compress, large_threshold, shard_key = nil)
      puts 'test'
    end

    # Sends a status update packet (op 3). This sets the bot user's status (online/idle/...) and game playing/streaming.
    # @param status [String] The status that should be set (`online`, `idle`, `dnd`, `invisible`).
    # @param since [Integer] The unix timestamp in milliseconds when the status was set. Should only be provided when
    #   `afk` is true.
    # @param game [Hash<Symbol => Object>, nil] `nil` if no game should be played, or a hash of `:game => "name"` if a
    #   game should be played. The hash can also contain additional attributes for streaming statuses.
    # @param afk [true, false] Whether the status was set due to inactivity on the user's part.
    def send_status_update(status, since, game, afk)
      puts 'test'
    end

    # Sends a voice state update packet (op 4). This packet can connect a user to a voice channel, update self mute/deaf
    # status in an existing voice connection, move the user to a new voice channel on the same server or disconnect an
    # existing voice connection.
    # @param server_id [Integer] The ID of the server on which this action should occur.
    # @param channel_id [Integer, nil] The channel ID to connect/move to, or `nil` to disconnect.
    # @param self_mute [true, false] Whether the user should itself be muted to everyone else.
    # @param self_deaf [true, false] Whether the user should be deaf towards other users.
    def send_voice_state_update(server_id, channel_id, self_mute, self_deaf)
      puts 'test'
    end

    # Resumes the session from the last recorded point.
    # @see #send_resume
    def resume
      puts 'test'
    end

    # Reconnects the gateway connection in a controlled manner.
    # @param attempt_resume [true, false] Whether a resume should be attempted after the reconnection.
    def reconnect(attempt_resume = true)
      puts 'test'
    end

    # Sends a resume packet (op 6). This replays all events from a previous point specified by its packet sequence. This
    # will not work if the packet to resume from has already been acknowledged using a heartbeat, or if the session ID
    # belongs to a now invalid session.
    #
    # If this packet is sent at the beginning of a connection, it will act similarly to an {#identify} in that it
    # creates a session on the current connection. Unlike identify however, this packet can also be sent in an existing
    # session and will just replay some of the events.
    # @param token [String] The token that was used to identify the session to resume.
    # @param session_id [String] The session ID of the session to resume.
    # @param seq [Integer] The packet sequence of the packet after which the events should be replayed.
    def send_resume(token, session_id, seq)
      puts 'test'
    end

    # Sends a request members packet (op 8). This will order Discord to gradually sent all requested members as dispatch
    # events with type `GUILD_MEMBERS_CHUNK`. It is necessary to use this method in order to get all members of a large
    # server (see `large_threshold` in {#send_identify}), however it can also be used for other purposes.
    # @param server_id [Integer] The ID of the server whose members to query.
    # @param query [String] If this string is not empty, only members whose username starts with this string will be
    #   returned.
    # @param limit [Integer] How many members to send at maximum, or `0` to send all members.
    def send_request_members(server_id, query, limit)
      puts 'test'
    end

    # Sends a custom packet over the connection. This can be useful to implement future yet unimplemented functionality
    # or for testing. You probably shouldn't use this unless you know what you're doing.
    # @param opcode [Integer] The opcode the packet should be sent as. Can be one of {Opcodes} or a custom value if
    #   necessary.
    # @param packet [Object] Some arbitrary JSON-serialisable data that should be sent as the `d` field.
    def send_packet(opcode, packet)
      puts 'test'
    end

    # Sends custom raw data over the connection. Only useful for testing; even if you know what you're doing you
    # probably want to use {#send_packet} instead.
    # @param data [String] The data to send.
    # @param type [Symbol] The type the WebSocket frame should have; either `:text`, `:binary`, `:ping`, `:pong`, or
    #   `:close`.
    def send_raw(data, type = :text)
      puts 'test'
    end

    private

    def setup_heartbeats(interval)
      puts 'test'
    end

    def connect_loop
      puts 'test'
    end

    # Separate method to wait an ever-increasing amount of time before reconnecting after being disconnected in an
    # unexpected way
    def wait_for_reconnect
      puts 'test'
    end

    # Create and connect a socket using a URI
    def obtain_socket(uri)
      puts 'test'
    end

    # Whether the URI is secure (connection should be encrypted)
    def secure_uri?(uri)
      %w[https wss].include? uri.scheme
    end

    # The port we should connect to, if the URI doesn't have one set.
    def socket_port(uri)
      puts 'test'
    end

    def find_gateway
      puts 'test'
    end

    def process_gateway
      puts 'test'
    end

    def connect
      puts 'test'
    end

    def websocket_loop
      puts 'test'
    end

    def handle_handshake_data(recv_data)
      puts 'test'
    end

    def handle_open; end

    def handle_error(e)
      puts 'test'
    end

    ZLIB_SUFFIX = "\x00\x00\xFF\xFF".b.freeze

    def handle_message(msg)
      puts 'test'
    end

    # Op 0
    def handle_dispatch(packet)
      puts 'test'
    end

    # Op 1
    def handle_heartbeat(packet)
      puts 'test'
    end

    # Op 7
    def handle_reconnect
      puts 'test'
    end

    # Op 9
    def handle_invalidate_session
      puts 'test'
    end

    # Op 10
    def handle_hello(packet)
      puts 'test'
    end

    # Op 11
    def handle_heartbeat_ack(packet)
      puts 'test'
    end

    # Called when the websocket has been disconnected in some way - say due to a pipe error while sending
    def handle_internal_close(e)
      puts 'test'
    end

    # Close codes that are unrecoverable, after which we should not try to reconnect.
    # - 4003: Not authenticated. How did this happen?
    # - 4004: Authentication failed. Token was wrong, nothing we can do.
    # - 4011: Sharding required. Currently requires developer intervention.
    FATAL_CLOSE_CODES = [4003, 4004, 4011].freeze

    def handle_close(e)
      puts 'test'
    end

    def send(data, type = :text)
      puts 'test'
    end

    def close(no_sync = false)
      puts 'test'
    end
  end
end
