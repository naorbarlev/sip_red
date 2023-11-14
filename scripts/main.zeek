module sip_red;

export {
	# Append the value LOG to the Log::ID enumerable.
	redef enum Log::ID += { LOG };

	## The record type which contains the fields of the SIP log.
	type Info: record {
		## Timestamp for when the request happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## Represents the pipelined depth into the connection of this
		## Verb used in the SIP request (INVITE, REGISTER etc.).
		method: string &log &default="-";
		## Contents of the Date: header from the client
		request_path: vector of string &log &optional;
		## The server message transmission path, as extracted from the headers.
		response_path: vector of string &log &optional;
		## Contents of the User-Agent: header from the client
		user_agent: string &log &default="-";
		## Status code returned by the server.
		status_code: count &log &optional;
		## Status message returned by the server.
		status_msg: string &log &default="-";
		## Contents of the Content-Length: header from the client
		request_body_len: count &log &optional;
		## Contents of the Content-Length: header from the server
		response_body_len: count &log &optional;
		## Contents of the Content-Type: header from the server
		content_type: string &log &default="-";
	};
}

event zeek_init()
	{
	# Create the logging stream.
	Log::create_stream(sip_red::LOG, [ $columns=sip_red::Info, $path="sip_red" ]);
	}

event sip_end_entity(c: connection, is_request: bool) &priority=0
	{
	#print c$sip;
	#print "---------------";
	if ( ! is_request )
		{
		if ( ! c$sip?$user_agent )
			c$sip$user_agent = "-";

		if ( ! c$sip?$content_type )
			c$sip$content_type = "-";

		local log: Info = [ $ts=network_time(), $uid=c$uid, $id=c$id,
		    $method=c$sip$method, $request_path=c$sip$request_path,
		    $response_path=c$sip$response_path,
		    $user_agent=c$sip$user_agent,
		    $status_code=c$sip$status_code,
		    $status_msg=c$sip$status_msg,
		    $request_body_len=c$sip$request_body_len,
		    $response_body_len=c$sip$response_body_len,
		    $content_type=c$sip$content_type ];
		Log::write(sip_red::LOG, log);
		}
	}
