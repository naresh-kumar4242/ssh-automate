#!/usr/bin/python

import sys
from pexpect import pxssh
import getpass
import re

def sshvm(servers,packages):
    try:
        with open('servers', 'r') as myfile:
            for i in range(2):
                (username,ip)=myfile.readline().replace('\n', '').split("@")
                
                s = pxssh.pxssh()
                s.login(ip,username)
                 
                s.sendline('sudo apt-get install elinks')
                s.sendline(getpass.getpass('Authorize yourself: '))
                s.sendline('Y')
                s.prompt()
                print s.before
                
                pack_file = open(packages, 'rU')
                for package in pack_file:
                    #check whether a package is installed or not before installing
                    s.sendline('dpkg --get-selections | grep %s'%package) 
                    s.prompt()
                    print s.before
                    match = re.search(r'\sinstall',s.before)
                    if match:
                        print "Already installed\n"
                    else:
                        s.sendline('sudo apt-get install %s'%package)
                        s.sendline('Y')
                        s.prompt()
                        print "%s package successfully installed"%(package)
                
                s.sendline('cowsay Mayank says DevOps is amazing! ')
                s.prompt()
                print s.before
                
                s.sendline('sudo useradd -m mayank')
                s.prompt()
                print "User mayank created "
            
                s.sendline('sudo passwd mayank')
                s.sendline(getpass.getpass('Enter password for new user: ')) 
                s.sendline(getpass.getpass('Enter password again: ')) 
                s.prompt()
            
                s.sendline('su -l mayank')
                print "\nLogging in with our new user mayank "
                s.sendline(getpass.getpass('\nTo login, Enter password for user mayank: '))
                s.prompt()

                s.sendline('mkdir testdir ; touch testfile ; ls -l')
                s.prompt()
                print s.before
                
                print 'All tasks executed successfully'
                
                s.sendline('logout')
                s.sendline('sudo poweroff')
                s.logout()
                s.close()

    except pxssh.ExceptionPxssh,e:
        print 'pxssh failed on login!'
        print str(e)
        
def main():
    if not sys.argv[1:]:
        print "Usage: [ username@serverIPaddress ] Or use 2 files to connect to multiple servers : [servers] [packages]"
        sys.exit(1)
    multiple_servers = sys.argv[1]
    packages = sys.argv[2]
    sshvm(multiple_servers,packages)

if __name__ == '__main__':
    main()
