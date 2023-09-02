# tiny11builder

Script to build a trimmed-down Windows 11 image.

This is a script to automate the build of a streamlined Windows 11 image, similar to tiny11.
My main goal is to use only Microsoft utilities like DISM, and nothing external. The only executable included is oscdimg.exe, which is provided in the Windows ADK and it is used to create bootable ISO images. Also included is an unattended answer file, which is used to bypass the Microsoft account on OOBE and to deploy the image with the /compact flag.
It's open-source, so feel free to add or remove anything you want! Feedback is also much appreciated.

In theory all Windows 11 ISOs are supported.

Instructions:

1. Download Windows 11 from the Microsoft website (<https://www.microsoft.com/software-download/windows11>)
2. Run `Start-Tiny11Builder.ps1` as an Administrator
3. Select the SKU that you want the image to be based on.
4. Sit back and relax :)
5. When the image is completed, you will see it in the folder where the script was executed, with the name `tiny11.iso`

What is removed:
Clipchamp,
News,
Weather,
Xbox (although Xbox Identity provider is still here, so it should be possible to be reinstalled with no issues),
GetHelp,
GetStarted,
Office Hub,
Solitaire,
PeopleApp,
PowerAutomate,
ToDo,
Alarms,
Mail and Calendar,
Feedback Hub,
Maps,
Sound Recorder,
Your Phone,
Media Player,
QuickAssist,
Internet Explorer,
LA57 support,
OCR for en-us,
Speech support,
TTS for en-us,
Media Player Legacy,
Tablet PC Math,
Wallpapers,
Edge,
OneDrive

Known issues:

1. Microsoft Teams (personal) and Cortana are still here. If you find a way to remove them before I find one, feel free to help!
2. Although Edge is removed, the icon and a ghost of its taskbar pin are still available. Also, there are some remnants in the Settings. But the app in itself is deleted.

And that's pretty much it for now!
Thanks for trying it and let me know how you like it!
