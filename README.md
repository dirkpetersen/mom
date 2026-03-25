# mom - Meta Overlay Manager


Allow a user to install packages on a system without giving them root access 

mom drives installation of apt-get or dnf and it is a tool that we want to give to end users so they can install software on a machine they do not have root on. 

The tool is written in Rust and that supports only two options stalling a package  Or updating a package This can be an unattended mode and refreshing the package repository The tool should not support adding other reositories This remains the priority of a sysadmin  Who should detect umm if should also not allow the installation of random RPM files or a files it should not allow the installation directly from Internet sources and it should also prevent post execution or injection via environment variables Before you even start coding do a thorough analysis on security requirements as this tool can be dangerous the tool has two operations mode either it will be set to set UID ROOT meaning that everybody with access to the tool will be able to execute it and it will execute as root and the other operations mode is a group membership in the MOM user group O users need to be added to the MOM user group could be eligible There can also be a configuration in etc To define membership in a different user group that would be eligible to execute this 
We need packages for for Debian as well as Red Enterprise 9 and 10 as well as Ubuntu 2204 2404 and 2604 These should be downloadable from Github 

can you please ask me questions about further requirements and do a sort of security analyst analysis before you start coding  can you please ask me questions about further requirements and do a sort of security analyst analysis before you start coding 
