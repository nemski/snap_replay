require 'openssl'

# SNMP datatypes
#
# INTEGER                                 = "\x02"
# OCTET_STRING                   = "\x04"
# NULL                                   = "\x00"
# OBJECT_IDENTIFIER         = "\x06"
# SEQUENCE                               = "\x30"

class SNMPObject
	attr_reader :response, :tag, :value

	def initialize(tag, value)
		@tag = tag
		@value = value.to_s

		@response = OpenSSL::ASN1::ASN1Data.new(@value, @tag, :UNIVERSAL)
	end

	def tag=(value)
		@tag = value
		@response = OpenSSL::ASN1::ASN1Data.new(@value, @tag, :UNIVERSAL)
	end

	def value=(value)
		@value = value.to_s
		@response = OpenSSL::ASN1::ASN1Data.new(@value, @tag, :UNIVERSAL)
	end
end

class SNMPTable
	def initialize()
		@hash_of_oids = {}
		@array_of_oids = []
	end

	def add(oid, tag, value)
		@hash_of_oids[oid] = SNMPObject.new(tag, value)
		@array_of_oids << oid
		@array_of_oids.sort!
	end

	def del(oid)
		@hash_of_oids.delete(oid)
	end

	def [](oid)
		@hash_of_oids[oid]
	end

	def getNext(oid)
		if @array_of_oids.index(oid).nil?
                        @tmp_array = @array_of_oids.clone
                        @tmp_array << oid
                        @tmp_array.sort!
			if @tmp_array.index(oid) == @tmp_array.rindex
				# Throw except "End of MIB"
				puts "End of MIB\n"
				exit
			end
                        @return = @array_of_oids[@tmp_array.index(oid)]
		else
			@next_index = @array_of_oids.index(oid)++
			@return = @hash_of_oids[@array_of_oids[@next_index]]
		end
		
		@return.response.to_der
	end

	def get(oid)
		
		@hash_of_oids[oid].response.to_der
	end
end
