require 'socket'

require_relative 'snap_parser'

#
# SNMP datatypes
#
ASN1DataTypes = {
   :"INTEGER-32"           			=>      2,
   :"OCTET-STRING"     				=> 		4,
   :NULL                           	=>      5,
   :"OBJ-ID"                       	=>      6,
   :SEQUENCE           				=> 		48,
   :"IP-ADDRESS"           			=>      64,
   :"COUNTER-32"           			=>      65,
   :"GAUGE-32"                     	=>      66,
   :"TIME-TICKS"           			=>      67,
   :"COUNTER-64"           			=>      70,

}

def parse_reply(pkt)
	return if not pkt[1]

	asn1 = OpenSSL::ASN1.decode(pkt) rescue nil
	if(! asn1)
	           puts "Not ASN encoded data"
	           return
	end

	msgVersion = asn1.value[0].value

	if msgVersion == 3
	  msgGlobalData = asn1.value[1]

	  msgData = asn1.value[3]
	  contextEngineID = msgData.value[0]
	  contextName = msgData.value[1]

	  pdu = msgData.value[2]

	elsif msgVersion == 1
		community = asn1.value[1]
		pdu = asn1.value[2]
		pduType = pdu.tag

	else
	puts "Only msgVersion 1 and 3 supported"
	puts msgVersion.methods
	return
	end

	requestId = pdu.value[0]
	errorStatus = pdu.value[1]
	errorIndex = pdu.value[2]
	varBind = pdu.value[3]

	if varBind
	    var = varBind.value[0]
	    if var
	       oid = var.value[0]
           val = var.value[1]
    	end
	end

	snmpResult = {  
		:msgAuthEngineID        => msgAuthoritiveEngineID,
        :msgAuthEngineBoots    	=> msgAuthoritiveEngineBoots,
        :msgAuthEngineTime      => msgAuthoritiveEngineTime,
		:contextEngineID        => contextEngineID,
		:msgVersion 			=> msgVersion,
		:pduType				=> pduType,
		:community				=> community,
		:requestId				=> requestId,
		:errorStatus            => errorStatus,
		:errorIndex				=> errorIndex,
		:oid                    => oid,
		:val                    => val,
    }
	
  snmpReturn
end

def gen_snmpMsg(snmpPacket)
	msgFlags, msgAuthEngineID, msgAuthEngineBoots, msgAuthEngineTime, userName, msgAuthParam, msgPrivParam, scopedPDU)

	if snmpPacket[:msgVersion] == 1
		pdu = [ OpenSSL::ASN1::Integer(snmpPacket[:requestId]), OpenSSL::ASN1::Integer(0), OpenSSL::ASN1::Integer(0), 
			OpenSSL::ASN1::Sequence( [	OpenSSL::ASN1::Sequence( [	OpenSSL::ASN1::ObjectId(snmpPacket[:oid]), snmpPacket[:val]		] )		] )
    	msg = [ OpenSSL::ASN1::Integer(snmpPacket[:msgVersion]), OpenSSL::ASN1::OctetString(snmpPacket[:community]), pdu ]
       
    wholeMsg = OpenSSL::ASN1::Sequence(msg).to_der

    wholeMsg
end

file = "~/test.snap"
agent = SNMPAgent.new

while (line = file.gets)
	oid, tag, value = line.split(/\s/)
	case tag
	when nil, [], "", 0
		puts "invalid line\n"
	else
		# A cheap way to convert our strings into symbols, which then act as a lookup table for ASN tag hex values
		tag = ASN1DataTypes[:"#{tag}"]
	end

	agent.add(oid, tag, value)
end

udp_socket = UDPSocket.new
udp_socket.bind("0.0.0.0", 1161)

while 1
	ret, sender = udp_socket.recvfrom(65535)

	snmpReturn = parse_reply(ret)

	case snmpReturn[:pduType]
	when 0
		reply = agent.get(snmpReturn[:oid])
		oid = snmpReturn[:oid]
	when 1
		oid, reply = agent.get_next(snmpReturn[:oid])
	else
		puts "Invalid request received"
		exit
	end

	puts reply

	snmpResponse = snmpReturn.clone
	snmpResponse[:val] = reply
	snmpResponse[:oid] = oid

	replyPkt = gen_snmpMsg(snmpResponse)

	udp_socket.send(data, 0, ret, 161)
end