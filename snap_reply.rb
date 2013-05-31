require_relative 'snap_parser'

#
# SNMP datatypes
#
ASN1DataTypes = {
	:"INTEGER-32"		=>	"\x02",
	:"OCTET-STRING"     =>	"\x04",
	:NULL				=>	"\x05",
	:"OBJ-ID"			=>	"\x06",
	:SEQUENCE           =>	"\x30",
	:"IP-ADDRESS"		=>	"\x40",
	:"COUNTER-32"		=>	"\x41",
	:"GAUGE-32"			=>	"\x42",
	:"TIME-TICKS"		=>	"\x43",
	:"COUNTER-64"		=>	"\x46",
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
