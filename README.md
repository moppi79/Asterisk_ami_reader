# Asterisk_ami_reader 

i use it to Block IPs from the Internet 

This tool Reads the Telnet Console from The Asterisk server. 
AMI is a Very powerfull tool, but I need it only to ban IP 


you need a Datebase table to save the Entrys 

SQL Code 

CREATE TABLE `blocklist` (
  `id` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `count` varchar(255) NOT NULL,
  `complete` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


