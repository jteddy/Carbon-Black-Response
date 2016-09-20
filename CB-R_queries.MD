# Carbon Black Response Queries

##### Programs launched from a shell or script that are network aware and not trusted. 
(process_name:powershell.exe OR parent_name:cmd.exe) AND netconn_count:[1 TO *] -alliance_score_srstruct:*

#####Services that are network aware and not trusted
parent_name:services.exe AND netconn_count:[1 TO *] -alliance_score_srstrust:*

#####Scheduled tasks that are network aware and not trusted
parent_name:taskeng.exe AND netconn_cont:[1 TO *] -alliance_score_srstrust:*

#####Non browsers connecting to foreign domains
(domain:.cn OR domain:.ru OR domain:.ir) -process_name:iexplore.exe -process_name:firefox.exe -process_name:chrome.exe -process_name:opera.exe

##### PsExec and variants
(process_name:psexec.exe OR process_name:rexec.exe OR process_name:rcmd.exe OR process_name:xcmd.exe)

##### Find lateral movement using SSH or RDP connections
(process_name:mstsc.exe OR process_name:ssh.exe)

##### Find lateral movement involving network share creation
cmdline:"net use"

##### Look for netcat and variants.
(process_name:netcat.exe OR process_name:ncat.exe OR cmdline:nc)

##### Unusual process manipulating pst files
filemod:*.pst AND -process_name:outlook.exe

##### Processes accessing the TOR network.
alliance_score_tor:*

##### Known malware that is network aware
alliance_score_virustotals:[5 TO *] AND netconn_count:[1 TO *]

##### Network aware, unsigned applications on sensitive systems
netconn_count:[1 TO *] AND -digsig_result:"Signed" AND (group:"<Domain Controllers>" OR group:"<DB Servers>"

##### Processes erasing the Master Boot Record
cmdline:"fdisk /mbr"

##### Unsigned processes encrypting files
-digsig_result:"Signed" AND cmdline:"cipher"

##### CryptoLocker
modload:rsaenh.dll process_name:*.exe filemod_count:[1000 TO *] path:AppData* regmod_count:]1 TO *] -process_name:chrome.exe -process_name:firefox.exe -process_name:iexplore.exe
