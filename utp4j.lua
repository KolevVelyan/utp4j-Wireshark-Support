-- declare protocol
utp4j_proto = Proto("utp4j", "Micro Transport Protocol for Java")

-- different message types
local message_types = {
    [0x01] = "DATA",
    [0x17] = "FIN",
    [0x21] = "STATE",
    [0x31] = "RST",
    [0x41] = "SYN",
}

-- create a function to dissect protocol
function utp4j_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < 20 then return end
    pinfo.desegment_len = 20 - buffer:len() -- header is 20 bytes long

    local offset = 0
    local message_type = buffer(offset, 1)

    if message_types[message_type:uint()] == nil then
        return
    end

    pinfo.cols.protocol = utp4j_proto.name
    local subtree = tree:add(utp4j_proto, buffer(), "uTP Protocol Data")

    offset = offset + 1
    local extension = buffer(offset, 1)
    offset = offset + 1
    local channel_id = buffer(offset, 2)
    offset = offset + 2
    local timestamp = buffer(offset, 4)
    offset = offset + 4
    local timestamp_difference = buffer(offset, 4)
    offset = offset + 4
    local window_size = buffer(offset, 4)
    offset = offset + 4
    local sequence_number = buffer(offset, 2)
    offset = offset + 2
    local ack_number = buffer(offset, 2)

    -- add the fields to the tree
    subtree:add(message_type, "Message Type: " .. message_types[message_type:uint()] .. " (" .. message_type:uint() .. ")")
    subtree:add(extension,  "Extension: " .. extension:uint())

    
    if message_types[message_type:uint()] == "DATA" then
        subtree:add(channel_id, "Receiving Channel ID: " .. channel_id:uint())
        subtree:add(timestamp, "Timestamp: " .. timestamp:uint())
        subtree:add(timestamp_difference, "Timestamp Difference: " .. timestamp_difference:uint() .. " [always 0]")
        subtree:add(window_size, "Data Left: " .. window_size:uint() .. " bytes")
        subtree:add(sequence_number, "Sequence Number: " .. sequence_number:uint())
        subtree:add(ack_number, "ACK Number: " .. ack_number:uint())
    elseif message_types[message_type:uint()] == "STATE" then
        subtree:add(channel_id, "Receiving/Sending Channel ID: " .. channel_id:uint())
        subtree:add(timestamp, "Timestamp: " .. timestamp:uint())
        subtree:add(timestamp_difference, "Timestamp Difference: " .. timestamp_difference:uint())
        subtree:add(window_size, "Window/Buffer Size: " .. window_size:uint())
        subtree:add(sequence_number, "Sequence Number: " .. sequence_number:uint())
        subtree:add(ack_number, "Ack Number: " .. ack_number:uint())
    elseif message_types[message_type:uint()] == "SYN" then
        subtree:add(channel_id, "Receiving Channel ID: " .. channel_id:uint())
        subtree:add(timestamp, "Timestamp: " .. timestamp:uint())
        subtree:add(timestamp_difference, "Timestamp Difference: " .. timestamp_difference:uint())
        subtree:add(window_size, "Window Size: " .. window_size:uint())
        subtree:add(sequence_number, "Sequence Number: " .. sequence_number:uint())
        subtree:add(ack_number, "Ack Number: " .. ack_number:uint())
    elseif message_types[message_type:uint()] == "FIN" then
        subtree:add(channel_id, "Receiving Channel ID: " .. channel_id:uint())
        subtree:add(timestamp, "Timestamp: " .. timestamp:uint())
        subtree:add(timestamp_difference, "Timestamp Difference: " .. timestamp_difference:uint())
        subtree:add(window_size, "Window Size: " .. window_size:uint())
        subtree:add(sequence_number, "Sequence Number: " .. sequence_number:uint())
        subtree:add(ack_number, "Ack Number: " .. ack_number:uint())
    elseif message_types[message_type:uint()] == "RST" then
        subtree:add(channel_id, "Receiving Channel ID: " .. channel_id:uint())
        subtree:add(timestamp, "Timestamp: " .. timestamp:uint())
        subtree:add(timestamp_difference, "Timestamp Difference: " .. timestamp_difference:uint())
        subtree:add(window_size, "Window Size: " .. window_size:uint())
        subtree:add(sequence_number, "Sequence Number: " .. sequence_number:uint())
        subtree:add(ack_number, "Ack Number: " .. ack_number:uint())
    end

end

-- register protocol to handle a specific udp port
udp_port = DissectorTable.get("udp.port")
udp_port:add(12345, utp4j_proto)