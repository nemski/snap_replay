snap_replay
===========

A simple SNMP Agent replay daemon, which accepts a SNAP capture file in the format of:
&lt;OID> &lt;SNMP_TYPE> &lt;VALUE>

Where the SNMP_TYPE is one of these values:
   :"INTEGER-32"             		=>      2,
   :"OCTET-STRING"     				  => 		  4,
   :NULL                        =>      5,
   :"OBJ-ID"                    =>      6,
   :SEQUENCE           				  =>      48,
   :"IP-ADDRESS"           			=>      64,
   :"COUNTER-32"           			=>      65,
   :"GAUGE-32"                  =>      66,
   :"TIME-TICKS"           			=>      67,
   :"COUNTER-64"           			=>      70,
