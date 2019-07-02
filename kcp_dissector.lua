-- author: yinkaisheng@live.com
-- for decoding kcp udp msg
require "bit32"

do
    kcp_parse_table = { }
    msg_header_size = 8

    function append_str(str, strformat, key, value)
        if string.len(str) == 0 or string.sub(str, -1, -1) == '{' then
            return str .. string.format(strformat, key, value)
        else
            return str .. ',' .. string.format(strformat, key, value)
        end
    end

    function parse_le_uint8(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 1):le_uint()
        col_str = append_str(col_str, '%s=%u', name, value)
        root:add_le(_G[protocol_type_name].fields[name], buf(start, 1))
        return start + 1, col_str
    end

    function parse_le_uint16(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 2):le_uint()
        col_str = append_str(col_str, '%s=%u', name, value)
        root:add_le(_G[protocol_type_name].fields[name], buf(start, 2))
        return start + 2, col_str
    end

    function parse_le_uint32(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 4):le_uint()
        col_str = append_str(col_str, '%s=%u', name, value)
        root:add_le(_G[protocol_type_name].fields[name], buf(start, 4))
        return start + 4, col_str
    end

    function parse_uint8(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 1):uint()
        col_str = append_str(col_str, '%s=%u', name, value)
        root:add(_G[protocol_type_name].fields[name], buf(start, 1))
        return start + 1, col_str
    end

    function parse_int16(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 2):int()
        col_str = append_str(col_str, '%s=%d', name, value)
        root:add(_G[protocol_type_name].fields[name], buf(start, 2))
        return start + 2, col_str
    end

    function parse_int32(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 4):int()
        col_str = append_str(col_str, '%s=%d', name, value)
        root:add(_G[protocol_type_name].fields[name], buf(start, 4))
        return start + 4, col_str
    end

    function parse_uint16(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 2):uint()
        col_str = append_str(col_str, '%s=%u', name, value)
        root:add(_G[protocol_type_name].fields[name], buf(start, 2))
        return start + 2, col_str
    end

    function parse_uint32(protocol_type_name, start, name, buf, pkt, root, col_str)
        local value = buf(start, 4):uint()
        col_str = append_str(col_str, '%s=%u', name, value)
        root:add(_G[protocol_type_name].fields[name], buf(start, 4))
        return start + 4, col_str
    end

    -- rtp video
    KCP_VIDEO_RTP_MSG_TYPE = 4738
    kcp_video_protocol_name = 'KCPVideo'
    kcp_video_protocol_desc = 'KCP Video Msg'
    ProtoKCPVideo = Proto(kcp_video_protocol_name, kcp_video_protocol_desc)
    field_kcp_length = ProtoField.uint32('KCP.Length', 'MsgLen', base.DEC)
    field_kcp_msgtype = ProtoField.uint32('KCP.MsgType', 'MsgType', base.DEC)
    field_rtp_payload = ProtoField.uint32('RTP.Payload', 'Payload', base.DEC)
    field_rtp_marker = ProtoField.uint32('RTP.Marker', 'Marker', base.DEC)
    field_rtp_seqno = ProtoField.uint32('RTP.SeqNO', 'SeqNo', base.DEC)
    field_rtp_timestamp = ProtoField.uint32('RTP.TimeStamp', 'TimeStamp', base.DEC)
    field_rtp_ssrc = ProtoField.uint32('HYP.SSRC', 'SSRC', base.DEC)
    field_rtp_data = ProtoField.bytes('RTP.Data', 'RtpData')

    ProtoKCPVideo.fields = {field_kcp_length, field_kcp_msgtype, field_rtp_seqno, field_rtp_timestamp, field_rtp_ssrc, field_rtp_data}

    function parse_udp_video(start, msg_type, kcp_data_len, buf, pkt, root)
        -- kcp_data_len = buf(20,4):le_uint()
        local payload_index = start+msg_header_size + 1
        local seqno_index = start+msg_header_size + 2
        local timestamp_index = start+msg_header_size + 4
        local ssrc_index = start+msg_header_size + 8
        local indicator_index = start+msg_header_size + 12--rtp head 12
        local second_byte_value = buf(payload_index, 1):uint()
        local rtp_payload = bit32.band(second_byte_value, 0x7F)-- or second_byte_value >> 1 -- require lua 5.3
        local rtp_marker = bit32.rshift(second_byte_value, 7)-- or second_byte_value & 1 -- require lua 5.3
        local rtp_seqno = buf(seqno_index, 2):uint()
        local rtp_timestamp = buf(timestamp_index, 4):uint()
        local rtp_ssrc = buf(ssrc_index, 4):uint()
        local indicator = buf(indicator_index, 1):uint()
        local indicator_type = bit32.band(indicator, 0x1F)
        local fu_start = 0
        local fu_end = 0
        if indicator_type == 28 then
            local fuheader_index = indicator_index + 1
            local fuheader = buf(fuheader_index, 1):uint()
            fu_start = bit32.rshift(fuheader, 7)
            fu_end = bit32.band(bit32.rshift(fuheader, 6), 1)
        end
        protocol_name = tostring(pkt.cols.protocol)
        if protocol_name ~= kcp_video_protocol_name then
            pkt.cols.protocol = kcp_video_protocol_name
        end
        local rtp_str = string.format(',SeqNo=%u,TimeStamp=%u,SSRC=%u,Payload=%u', rtp_seqno, rtp_timestamp, rtp_ssrc, rtp_payload)
        if fu_start == 1 then
            rtp_str = rtp_str .. ',Start=1'
        end
        if fu_end == 1 then
            rtp_str = rtp_str .. ',End=1'
        end
        if rtp_marker == 1 then
            rtp_str = rtp_str .. ',Marker=1'
        end
        col_str = tostring(pkt.cols.info) .. rtp_str
        pkt.cols.info = col_str
        local t = root:add(ProtoKCPVideo, buf(start, kcp_data_len))
        t:add(field_kcp_length, buf(start, 4))
        t:add(field_kcp_msgtype, buf(start + 4, 4))
        t:add(field_rtp_seqno, buf(seqno_index, 2))
        t:add(field_rtp_timestamp, buf(timestamp_index, 4))
        t:add(field_rtp_ssrc, buf(ssrc_index, 4))
        t:add(field_rtp_data, buf(start + msg_header_size, kcp_data_len - msg_header_size))
        return start + kcp_data_len - msg_header_size, col_str
    end

    kcp_parse_table[KCP_VIDEO_RTP_MSG_TYPE] = parse_udp_video

    -- kcp
    kcp_conv_table = {}
    kcp_head_size = 28
    kcp_header_protocol_name = 'KCPHeader'
    kcp_header_protocol_desc = 'KCP Header'
    ProtoKCPHeader = Proto(kcp_header_protocol_name, kcp_header_protocol_desc)
    KCPHeaders = {
            {'conv',    ProtoField.uint32, parse_le_uint32, base.DEC}, -- default DEC, can be omitted
            {'cmd',     ProtoField.uint32, parse_le_uint8,  base.DEC},
            {'frg',     ProtoField.uint32, parse_le_uint8,  base.DEC},
            {'wnd',     ProtoField.uint32, parse_le_uint16, base.DEC},
            {'ts',      ProtoField.uint32, parse_le_uint32, base.DEC},
            {'sn',      ProtoField.uint32, parse_le_uint32, base.DEC},
            {'una',     ProtoField.uint32, parse_le_uint32, base.DEC},
            {'len',     ProtoField.uint32, parse_le_uint32, base.DEC},
            {'snd_una', ProtoField.uint32, parse_le_uint32, base.DEC},
        }
    for key, value in pairs(KCPHeaders) do
        local field = value[2](kcp_header_protocol_name .. '.' .. value[1], value[1])
        ProtoKCPHeader.fields[value[1]] = field
    end

    function parse_kcp(start, msg_type, kcp_len, buf, pkt, root)
        local buf_len = buf:len()
        protocol_name = tostring(pkt.cols.protocol)
        if protocol_name == 'UDP' then
            pkt.cols.protocol = kcp_header_protocol_name
        end
        local kcp_conv = buf(start, 4):le_uint()
        kcp_conv_table[kcp_conv] = 1
        local tree = root:add(ProtoKCPHeader, buf(start, kcp_head_size))
        col_str = '{'
        for key, value in pairs(KCPHeaders) do
            start, col_str = value[3]('ProtoKCPHeader', start, value[1], buf, pkt, tree, col_str)
        end
        col_str = col_str .. '}'
        old_str = tostring(pkt.cols.info)
        if string.find(old_str, '{conv') == nil then
            fs, fe = string.find(old_str, ' → ')
            if fe == nil then
                pkt.cols.info = col_str
            else
                fs, fe = string.find(old_str, ' ', fe + 1)
                if fs == nil then
                    pkt.cols.info = col_str
                else
                    pkt.cols.info = string.sub(old_str, 1, fs) .. col_str
                end
            end
        else
            col_str = old_str .. col_str
            pkt.cols.info = col_str
        end
        if start + msg_header_size <= buf_len then
            local kcp_data_len = buf(start, 4):uint()
            msg_type = buf(start + 4, 4):uint()
            if kcp_len == kcp_data_len and start + kcp_data_len <= buf_len then
                local parse_func = kcp_parse_table[msg_type]
                if parse_func then
                    start_new, col_str = parse_func(start, msg_type, kcp_data_len, buf, pkt, root)
                else
                    pkt.cols.info = tostring(pkt.cols.info) .. string.format(', no parse function for msg type %u', msg_type)
                end
                start = start + kcp_data_len
                if start + kcp_head_size <= buf_len then
                    kcp_conv = buf(start, 4):le_uint()
                    kcp_len = buf(start + 20, 4):le_uint()
                    if kcp_conv_table[kcp_conv] == 1 then
                        parse_kcp(start, 0, kcp_len, buf, pkt, root)
                    else
                    end
                end
            else
                if start + kcp_head_size <= buf_len then
                    kcp_conv = buf(start, 4):le_uint()
                    kcp_len = buf(start + 20, 4):le_uint()
                    if kcp_conv_table[kcp_conv] == 1 then
                        parse_kcp(start, 0, kcp_len, buf, pkt, root)
                    else
                    end
                end
            end
        end
        return start, col_str
    end

    -- protocol
    kcp_protocol_name = 'KCP'
    kcp_protocol_desc = 'KCP Protocol'
    ProtoKCP = Proto(kcp_protocol_name, kcp_protocol_desc)

    -- dissector
    function ProtoKCP.dissector(buf, pkt, root)
        local buf_len = buf:len()
        if buf_len < msg_header_size then
            return
        end
        protocol_name = tostring(pkt.cols.protocol)
        local data_len = buf(0, 4):uint()
        if buf_len == data_len then
            local msg_type = buf(4, 4):uint()
            local parse_func = kcp_parse_table[msg_type]
            if parse_func then
                parse_func(0, msg_type, buf_len, buf, pkt, root)
            else
                pkt.cols.info = tostring(pkt.cols.info) .. string.format(', no parse function for msg id %u', msg_type)
            end
        elseif kcp_head_size + 8 <= buf_len then
            data_len = buf(20, 4):le_uint()
            local kcp_data_len = buf(kcp_head_size, 4):uint()
            if data_len == kcp_data_len then
                parse_kcp(0, 0, data_len, buf, pkt, root)
            else
                local kcp_conv = buf(0, 4):le_uint()
                if kcp_conv_table[kcp_conv] == 1 then
                    parse_kcp(0, 0, data_len, buf, pkt, root)
                else
                end
            end
        elseif kcp_head_size <= buf_len then
            local kcp_conv = buf(0, 4):le_uint()
            if kcp_conv_table[kcp_conv] == 1 then
                parse_kcp(0, 0, data_len, buf, pkt, root)
            else
            end
        else
        end
    end

    local udp_table = DissectorTable.get('udp.port')
    udp_table:add('61961', ProtoKCP)
end
