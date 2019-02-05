# script.py
#
# McGuire CyberPatriot Team
# Created 23 January 2017
# Last Modified 23 Jan 2017
# 
# INSTALLATION/UPDATE COMMANDS:
# apt-get update
# apt-get upgrade
# apt-get dist-upgrade
# apt-get install ufw
# apt-get install bum
#
# COMMANDS:
# find -iname *.mp3 > ~/Desktop/mp3.data
# dpkg -l ...


import os
import subprocess
import pwd, grp
from tkinter import *
from threading import Thread
from time import sleep
#sys.excepthook = lambda *args: None


curuser_password = "cyberpatriot"
pass_prefix = "CyberPatriot20"
pass_suffix = "!"
counter = 17

home_dir = input('Enter home directory: ')


INSTALLATION_UPDATE_COMMANDS = [
	"apt-get update -y",
	"apt-get upgrade -y",
	"apt-get dist-upgrade -y",
	"apt-get install ufw -y",
	"apt-get install bum -y",
	"apt-get install nmap -y",
	"apt-get install libpam-cracklib -y",
	"apt-get autoremove -y",
]

COMMANDS = [
	"cat /proc/meminfo",
	"cat /proc/cpuinfo",
	"cat /proc/version",
	"find -iname *.mp3",
	"find -iname *.php",
	"ps aux",
	"service --status-all",
	"crontab -l",
]

POST_INSTALL_COMMANDS = [
	"ufw enable",
	"ufw status verbose",
	"nmap -sT -O localhost",
	"apt-get purge nmap -y",
]








class CustomWindow:


	def __init__(self, master, log, home_dir, gridx=0, gridy=0):
		self.f = open(log, 'w+')
		self.home_dir = home_dir
		self.root = Frame(master)
		self.scrollbar = Scrollbar(self.root)
		self.scrollbar.pack(side=RIGHT,fill=Y)
		self.text = Text(self.root, wrap=WORD, yscrollcommand=self.scrollbar.set)
		self.text.bind("<Key>", lambda e: "break")
		self.text.pack()
		self.text.tag_config('cmd', foreground='red')
		self.text.tag_config('comment', foreground='blue')
		self.text.tag_config('end', foreground='black', background='green')
		self.text.tag_config('warn', foreground='black', background='red')
		self.scrollbar.config(command=self.text.yview)
		self.root.grid(row=gridx, column=gridy)


	def ewrite(self, text, tag=None):
		if not text.endswith('\n') and tag != 'end':
			text += '\n'
		self.text.insert(END, text)
		self.f.write(text)
		if tag != None:
			self.search(self.text, text, tag)
		self.text.see(END)

	def ewrite_string(self, text, tag=None):
		self.text.insert(END, text)
		self.f.write(text)
		if tag != None:
			self.search(self.text, text, tag)
		self.text.see(END)

	def ewrite_title(self, text, tag=None):
		text += "\n\n"
		self.text.insert(END, text)
		self.f.write(text)
		if tag != None:
			self.search(self.text, text, tag)
		self.text.see(END)

	def ewrite_break(self):
		text = '\n'
		self.text.insert(END, text)
		self.f.write(text)
		self.text.see(END)

	def ewrite_list(self, list, tag=None):
		for text in list:
			text = str(text)+'\n'
			self.text.insert(END, text)
			self.f.write(text)
			if tag != None:
				self.search(self.text, text, tag)
			self.text.see(END)


	def runcmd(self, cmd):
		cmdline = "# "+cmd
		self.ewrite_title(cmdline, tag='cmd')
		proc = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE)
		while True:
			line = proc.stdout.readline().decode('utf-8')
			if line != '':
				self.ewrite(line)
			if line == '' and proc.poll() != None:
				break
		self.text.insert(END, "\n")
		self.text.see(END)


	def search(self, text, keyword, tag):
		pos = '1.0'
		while True:
			idx = self.text.search(keyword, pos, END)
			if not idx:
				break
			pos = '{}+{}c'.format(idx, len(keyword))
			self.text.tag_add(tag, idx, pos)


	def window(self):
		pass


	def run(self):
		self.t = Thread(target=self.window)
		self.t.daemon = True
		self.t.start()


	def cleanup(self):
		self.ewrite("DONE", tag='end')
		self.f.close()




















class UsersWindow(CustomWindow):


	def __init__(self, master, log, userfile, adminfile, password_counter, home_dir, grid_x=0, grid_y=0):
		super().__init__(master, log, home_dir, gridx=grid_x, gridy=grid_y)
		self.userfile = userfile
		self.adminfile = adminfile
		self.counter = password_counter


	def deluser(self, username):
		self.runcmd('userdel ' + username)
		

	def adduser(self, username):
		self.runcmd('useradd -m -U -s /bin/bash -p CyberPatriot2017! ' + username)


	def addadmin(self, username):
		self.runcmd('adduser ' + username + ' sudo')


	def removeadmin(self, username):
		self.runcmd('gpasswd -d ' + username + ' sudo')

	def changepass(self, username):
		self.ewrite("Setting password of user '"+username+"' to 'CyberPatriot2017!'")
		os.system("usermod -p $(openssl passwd CyberPatriot2017!) " + username)


	def loginDefs(self):
		f = open('/etc/login.defs', 'r')
		lines = f.readlines()
		f.close()
		config = []
		for i in range(len(lines)):
			if lines[i].startswith('PASS_MAX_DAYS'):
				lines[i] = 'PASS_MAX_DAYS\t90\n'
				config.append(lines[i])
			if lines[i].startswith('PASS_MIN_DAYS'):
				lines[i] = 'PASS_MIN_DAYS\t10\n'
				config.append(lines[i])
			if lines[i].startswith('PASS_WARN_AGE'):
				lines[i] = 'PASS_WARN_AGE\t7\n'
				config.append(lines[i])
		f = open('/etc/login.defs', 'w')
		f.writelines(lines)
		f.close()
		self.ewrite("Configured following password age(in /etc/login.defs):", tag='comment')
		self.ewrite_list(config)
		self.ewrite_break()

	def commonAuth(self):
		text = "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800"
		if not open('/etc/pam.d/common-auth', 'r').read().split('\n')[-1].startswith(text):
			f = open('/etc/pam.d/common-auth', 'a')
			f.write('\n\n' + text)
			f.close()
			self.ewrite("Added following config to /etc/pam.d/common-auth", tag='comment')
			self.ewrite(text)
			self.ewrite_break()
		else:
			self.ewrite('/etc/pam.d/common-auth config already exists!', tag='comment')

	def commonPass(self):
		self.ewrite('Waiting for updates/upgrades/installations to finish...')
		while open(self.home_dir+'status').read() == "0":
			pass
		f = open('/etc/pam.d/common-password', 'r')
		lines = f.read().split('\n')
		f.close()
		for i in range(len(lines)):
			if 'pam_unix.so' in lines[i]:
				lines[i] += ' remember=5 minlen=8'
			if 'pam_cracklib.so' in lines[i]:
				lines[i] += ' ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1'
		f = open(f.name, 'w')
		f.writelines(lines)
		f.close()
		self.ewrite_break()
		self.ewrite('Set /etc/pam.d/common-password configurations...')
		self.ewrite('Password History        -> 5')
		self.ewrite('Password Minimum Length -> 8')
		self.ewrite('Password Complexity     -> >=1 Upper, >=1 Lower, >=1 Digit, >=1 Symbol')


	def window(self):
		# Users
		self.ewrite_title("Checking user authorization...", tag='comment')
		self.ewrite("Authorized Users:", tag='comment')
		authorized_users = []
		for user in open(self.userfile, 'r').read().split('\n')[1:]:
			if user != '':
				authorized_users.append(user)
		self.ewrite_list(authorized_users)
		self.ewrite_break()
		self.ewrite("Existing users:", tag='comment')
		sysusers = []
		for p in pwd.getpwall():
			self.f.write(str(p)+"\n")
			if p[2] >= 1000 and p[2] < 2000:
				sysusers.append(p[0])
				self.ewrite(p[0])
		unauth_users = []
		for user in sysusers:
			if user not in authorized_users:
				unauth_users.append(user)
		self.ewrite_break()
		if len(unauth_users) > 0:
			self.ewrite("Unauthorized users:", tag='warn')
			self.ewrite_list(unauth_users)
			self.ewrite_break()
		for user in unauth_users:
			self.deluser(user)
		uta = [] # users to add
		for user in authorized_users:
			if user not in sysusers:
				uta.append(user)
		if len(uta) > 0:
			self.ewrite("Users to add:", tag='comment')
			self.ewrite_list(uta)
			self.ewrite_break()
		for user in uta:
			self.adduser(user)
		#authorized_users.append('root')
		for user in authorized_users:
			self.changepass(user)

		# Admins
		self.ewrite_title("Checking admins...", tag='comment')
		self.ewrite("Authorized Admins:", tag='comment')
		authorized_admins = []
		for user in open(self.adminfile, 'r').read().split('\n')[1:]:
			if user != '':
				authorized_admins.append(user)
		self.ewrite_list(authorized_admins)
		self.ewrite_break()
		sysadmins = []
		for i in grp.getgrall():
			if i[0] == 'sudo':
				sysadmins = i[3]
		self.ewrite("Existing admins(in group 'sudo'):", tag='comment')
		self.ewrite_list(sysadmins)
		self.ewrite_break()
		unauth_admins = []
		for user in sysadmins:
			if user not in authorized_admins:
				unauth_admins.append(user)
		if len(unauth_admins) > 0:
			self.ewrite("Unauthorized admins:", tag='warn')
			self.ewrite_list(unauth_admins)
			self.ewrite_break()
		for user in unauth_admins:
			self.removeadmin(user)
		uta = [] # admins to add
		for user in authorized_admins:
			if user not in sysadmins:
				uta.append(user)
		if len(uta) > 0:
			self.ewrite("Admins to add:", tag='comment')
			self.ewrite_list(uta)
			self.ewrite_break()
		for user in uta:
			self.addadmin(user)
		self.ewrite_break()

		# Policy Section
		self.ewrite_title("Configuring password policies...", tag='comment')
		self.loginDefs()
		self.ewrite_break()
		self.commonAuth()
		self.ewrite_break()
		self.commonPass()

		self.ewrite_break()
		self.cleanup()











class SysWindow(CustomWindow):


	def __init__(self, master, cmds, log, home_dir, grid_x=0, grid_y=0):
		super().__init__(master, log, home_dir, gridx=grid_x, gridy=grid_y)
		self.cmds = cmds


	def fileSearch(self):
		f = open(self.home_dir+'fileextensions.dat')
		exts = f.read().split('\n')[1:]
		f.close()
		for dir, subdir, files in os.walk('/home/'):
			for file in files:
				for ext in exts:
					if file.endswith(ext):
						os.remove(os.path.join(dir, file))
						self.ewrite("Removed " + ext + " file: " + os.path.join(dir, file))


	def checkPkgs(self):
		# load search queries
		f = open(self.home_dir+'badpackages.dat')
		pkgs = f.read().split('\n')[1:]
		for i in pkgs:
			if i == '':
				pkgs.remove(i)
		f.close()
		proc = subprocess.Popen("dpkg -l", stdout=subprocess.PIPE, shell=True)
		(out, err) = proc.communicate()
		out = out.decode('utf-8').lower()
		lines = out.split("\n")
		for line in lines:
			for pkg in pkgs:
				if pkg in line:
					self.ewrite_string('BAD PACKAGE FOUND:', tag='warn')
					self.ewrite(' ' + line.split()[1] + ' \n' + line + '\n')
					self.runcmd('dpkg --purge ' + line.split()[1])


	def secureSSH(self):
		f = open('/etc/ssh/sshd_config', 'w')
		f.write("""
Port 2222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_key
ServerKeyBits 1024
LoginGraceTime 600
KeyRegenerationInterval 3600
PermitRootLogin no
IgnoreRhosts yes
IgnoreUserKnownHosts yes
StrictModes yes
X11Forwarding no
PrintMotd yes
SyslogFacility AUTH
LogLevel INFO
RhostsAuthentication no
RhostsRSAAuthentication no
RSAAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no""")
		f.close()


	def window(self):
		for cmd in self.cmds:
			self.runcmd(cmd)
		self.ewrite_break()
		self.fileSearch()
		self.ewrite_break()
		self.checkPkgs()
		self.ewrite_break()
		self.secureSSH()
		self.ewrite_break()
		self.cleanup()








class InstallationWindow(CustomWindow):


	def __init__(self, master, cmds, log, home_dir, grid_x=0, grid_y=0):
		super().__init__(master, log, home_dir, gridx=grid_x, gridy=grid_y)
		self.cmds = cmds


	def writeStatusValue(self, val):
		f = open(self.home_dir+'status', 'w')
		f.write(val)
		f.close()


	def window(self):
		self.writeStatusValue('0')
		for cmd in self.cmds:
			self.runcmd(cmd)
		self.cleanup()
		self.writeStatusValue('1')







class PostCMDWindow(CustomWindow):


	def __init__(self, master, cmds, log, home_dir, grid_x=0, grid_y=0):
		super().__init__(master, log, home_dir, gridx=grid_x, gridy=grid_y)
		self.cmds = cmds


	def window(self):
		for cmd in self.cmds:
			self.runcmd(cmd)
		self.cleanup()













def waitRun(thread, window):
	while thread.isAlive():
		pass
	window.run()


def run():
	os.chdir('/')
	root = Tk()
	root.wm_title("CyberPatriot Debian 7 Wheezy Script")
	iuc_window = InstallationWindow(root, INSTALLATION_UPDATE_COMMANDS, home_dir+'apt.data', home_dir, grid_x=0, grid_y=0)
	iuc_window.run()
	c_window = SysWindow(root, COMMANDS, home_dir+'commands.data', home_dir, grid_x=1, grid_y=0)
	c_window.run()
	aiuc_window = PostCMDWindow(root, POST_INSTALL_COMMANDS, home_dir+'post_commands.data', home_dir, grid_x=1, grid_y=1)
	wpi = Thread(target=waitRun, args=(iuc_window.t,aiuc_window))
	wpi.start()
	userWindow = UsersWindow(root, home_dir+'users.data', home_dir+'authorized_users.dat', home_dir+'authorized_admins.dat', counter, home_dir, grid_x=0, grid_y=1)
	userWindow.run()
	mainloop()


run()
