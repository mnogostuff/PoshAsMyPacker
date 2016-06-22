# Generate [0-9][0-9]... etc. for 
# num items in rec bin,
# num items no desktop
# num programs installed
# also record resolution - multiple monitors is a pretty great sign of legitimacy
# write function to wait on mouse click
# GetTickCount

Function WaitOnKeypress
{
    return $True
}

function Get-ScreenResolution {            
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")            
    [void] [Reflection.Assembly]::LoadWithPartialName("System.Drawing")            
    $Screens = [system.windows.forms.screen]::AllScreens            

    foreach ($Screen in $Screens) {            
        $DeviceName = $Screen.DeviceName            
        $Width  = $Screen.Bounds.Width            
        $Height  = $Screen.Bounds.Height            
        $IsPrimary = $Screen.Primary            

        $OutputObj = New-Object -TypeName PSobject             
        $OutputObj | Add-Member -MemberType NoteProperty -Name DeviceName -Value $DeviceName            
        $OutputObj | Add-Member -MemberType NoteProperty -Name Width -Value $Width            
        $OutputObj | Add-Member -MemberType NoteProperty -Name Height -Value $Height            
        $OutputObj | Add-Member -MemberType NoteProperty -Name IsPrimaryMonitor -Value $IsPrimary            
        $OutputObj            

    }            
}

function Get-ItemsOnDesktop
{
    $ret = Get-ChildItem -Path $ENV:USERPROFILE/Desktop
}

Function Get-CurrentRam
{
    Get-WMIObject -class win32_physicalmemory | Format-Table devicelocator, capacity -a
}

Function Get-RecycleBin
{
    # http://baldwin-ps.blogspot.be/2013/07/empty-recycle-bin-with-retention-time.html
}
# Get-WmiObject -Class Win32_Product | Select-Object -Property Name
# Get-WmiObject Win32_PnPSignedDriver| select devicename, driverversion
# Get Windows Version, get installed date
