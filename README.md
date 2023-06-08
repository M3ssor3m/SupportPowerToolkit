# SupportPowerToolkit

Hi, if you've found this then thank you for taking the time to look at my work!

I'm a novice programmer and used to work within the IT support industry.

I kept seeing the same issues coming into the helpdesk and wanted away to stop them reoccurring. 

A few month ago I decided to attempt to learn PowerShell and started piecing my scripts together into this master script. 

Some of the code within this script has already been tried and tested within estates. The desired outcome was achieved with excellent feedback from users. 

The master script is a concept, isn't complete, needs further details from admin to function properly and as stated I'm not a programmer but will use PSScriptAnalyzer to minimise faults. 

I've looked at numerous ways of executing this script from a GUI, Task Bar, GPO, etc but I think the best way of execution is remotely with Immediate Task Scheduler and GPO. In this case we shouldn't need to pass credentials and the script should run as admin on startup with GP.

I've also looked at different script formats to see which will execute the quickest. If you look at previous versions, you might see a completely different layout to the script. 

I've created this script into a module and uploaded it to the PowerShell gallery, which can be easily imported and executed with one command or ran remotely. Please note I haven't imported the latest version which is 0.1.2

https://www.powershellgallery.com/packages/Maintenance/0.1.2

With the release of ChatGPT4 I'm hoping to use this tool and others like Copilot to create a comprehensive cross platform maintenance script.

The script will query the OS and perform the necessary tasks, compile any errors into a log file, check conditions for issues and report any found issues to helpdesk via email, Slack and Teams. 

I wish I had more time to commit to the completion but I've just had twins. I will reply to any comments in due course. 

If anyone is interested in collaboration just drop me an email at Chris.mcdonald19@pm.me