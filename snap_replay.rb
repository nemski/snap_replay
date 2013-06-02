require 'socket'

require_relative 'snap_parser'

#
# SNMP datatypes
#
ASN1DataTypes = {
       :"INTEGER-32"           =>      2,
       :"OCTET-STRING"     =>  4,
       :NULL                           =>      5,
       :"OBJ-ID"                       =>      6,
       :SEQUENCE           =>  48,
       :"IP-ADDRESS"           =>      64,
       :"COUNTER-32"           =>      65,
       :"GAUGE-32"                     =>      66,
       :"TIME-TICKS"           =>      67,
       :"COUNTER-64"           =>      70,

}

if ! ARGV[0]
	puts "Usage: #{$0} <snmp snap>\n"
	exit
end

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

	  snmpResult = {  "msgAuthEngineID"               => msgAuthoritiveEngineID,
                               "msgAuthEngineBoots"    => msgAuthoritiveEngineBoots,
                               "msgAuthEngineTime"             => msgAuthoritiveEngineTime,
                               "contextEngineID"          => contextEngineID,
                               "errorStatus"              => errorStatus,
                               "oid"                              => oid,
                               "val"                              => val,
               }
  elsif msgVersion == 1
	community = asn1.value[1]
	pdu = asn1.value[2]
	
	snmpResult = {  "pdu"		=> pdu,
			"community"	=> community,
		}
  else
	puts "Only msgVersion 1 and 3 supported"
	puts msgVersion.methods
	return
  end
	
  snmpResult
end

file = File.new(ARGV[0])
agent = SNMPAgent.new

while (line = file.gets)
	oid, tag, value = line.split(/\s/)
	case tag
	when nil, [], "", 0
		puts "invalid line\n"
		next
	else
		# A cheap way to convert our strings into symbols, which then act as a lookup table for ASN tag hex values
		tag = ASN1DataTypes[:"#{tag}"]
	end

	agent.add(oid, tag, value)
end

udp_socket = UDPSocket.new
udp_socket.bind("0.0.0.0", 1161)
ret, sender = udp_socket.recvfrom(65535)

snmpReturn = parse_reply(ret)

puts snmpReturn

