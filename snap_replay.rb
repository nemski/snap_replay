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
		community = asn1.value[1].value
		pdu = asn1.value[2]
		pduType = pdu.tag

	else
	puts "Only msgVersion 1 and 3 supported"
	puts msgVersion.methods
	return
	end

	requestId = pdu.value[0].value
	errorStatus = pdu.value[1].value
	errorIndex = pdu.value[2].value
	varBind = pdu.value[3]

	if varBind
	    var = varBind.value[0]
	    if var
	       oid = var.value[0].value
           val = var.value[1]
    	end
	end

	snmpResult = {  
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
	
  snmpResult
end

def gen_snmpMsg(snmpPacket)

	pdu = [ OpenSSL::ASN1::Integer(snmpPacket[:requestId]), OpenSSL::ASN1::Integer(0), OpenSSL::ASN1::Integer(0), OpenSSL::ASN1::Sequence( [	OpenSSL::ASN1::Sequence( [ OpenSSL::ASN1::ObjectId(snmpPacket[:oid]), OpenSSL::ASN1::ASN1Data.new(snmpPacket[:val], snmpPacket[:tag], :CONTEXT_SPECIFIC)	] )	] ) ]

	scopedPdu = OpenSSL::ASN1::ASN1Data.new(pdu, 2, :CONTEXT_SPECIFIC)
	msg = [ OpenSSL::ASN1::Integer(snmpPacket[:msgVersion]), OpenSSL::ASN1::OctetString(snmpPacket[:community]), scopedPdu ]
       
    wholeMsg = OpenSSL::ASN1::Sequence(msg).to_der

    wholeMsg
end

file = File.new(ARGV[0])
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
		oid, tag, reply = agent.get(snmpReturn[:oid])
	when 1
		oid, tag, reply = agent.get_next(snmpReturn[:oid])
	else
		puts "Invalid request received"
		exit
	end

	snmpResponse = snmpReturn.clone
	snmpResponse[:tag] = tag
	snmpResponse[:val] = reply
	snmpResponse[:oid] = oid

	snmpResponse.each_pair {|key,value| puts "#{key} = #{value} (#{value.class}"}

	replyPkt = gen_snmpMsg(snmpResponse)

	puts "Sending to #{sender[2]}:#{sender[1]}"

	udp_socket.send(replyPkt, 0, sender[2], sender[1])
end
