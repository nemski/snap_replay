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

agent.get(".1.3.6.1.2.1.1.1.0")
