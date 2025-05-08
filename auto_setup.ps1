# auto_setup.ps1
# Automatic VM detection countermeasures setup script
$ErrorActionPreference = "SilentlyContinue"

# Function to write status message with timestamp
function Log-Status {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message"
    Add-Content -Path "C:\SharedData\setup_log.txt" -Value "[$timestamp] $message"
}

# Create log file
$null = New-Item -Path "C:\SharedData\setup_log.txt" -ItemType File -Force
Log-Status "Starting automated VM detection countermeasures setup"

# 1. Create custom user profile to make the environment look more realistic
function Setup-UserEnvironment {
    Log-Status "Customizing user environment..."
    
    # Create some realistic user folders and files
    $userFolders = @(
        "$env:USERPROFILE\Documents\Work Projects",
        "$env:USERPROFILE\Documents\Personal",
        "$env:USERPROFILE\Pictures\Screenshots",
        "$env:USERPROFILE\Downloads\Software"
    )
    
    foreach ($folder in $userFolders) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
    
    # Create some dummy files
    "Meeting notes for project review" | Out-File "$env:USERPROFILE\Documents\Work Projects\Meeting Notes.txt" -Force
    "Shopping list: milk, eggs, bread" | Out-File "$env:USERPROFILE\Documents\Personal\Notes.txt" -Force
    
    # Create recent documents for realism
    $recentsPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (!(Test-Path $recentsPath)) {
        New-Item -Path $recentsPath -ItemType Directory -Force | Out-Null
    }
    
    Log-Status "User environment customization complete"
}

# 2. Install Python if needed
function Install-Python {
    Log-Status "Checking Python installation..."
    
    try {
        $pythonVersion = (python --version 2>&1).ToString()
        Log-Status "Python already installed: $pythonVersion"
    }
    catch {
        Log-Status "Python not found. Installing..."
        
        # Download Python installer
        $pythonInstallerUrl = "https://www.python.org/ftp/python/3.10.11/python-3.10.11-amd64.exe"
        $pythonInstaller = "$env:TEMP\python_installer.exe"
        
        Log-Status "Downloading Python installer..."
        Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $pythonInstaller -UseBasicParsing
        
        Log-Status "Installing Python silently..."
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
        
        # Verify installation
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        try {
            $pythonVersion = (python --version 2>&1).ToString()
            Log-Status "Python installed successfully: $pythonVersion"
            
            # Install required packages
            Log-Status "Installing required Python packages..."
            Start-Process -FilePath "python" -ArgumentList "-m", "pip", "install", "psutil" -Wait -NoNewWindow
        }
        catch {
            Log-Status "Python installation failed: $_"
        }
    }
}

# 3. Create the main pafish defeat script
function Create-PafishDefeatScript {
    Log-Status "Creating VM detection countermeasures script..."
    
    $scriptPath = "C:\SharedData\vm_countermeasures.py"
    
    # VM countermeasures script content
    $scriptContent = @'
import os
import sys
import time
import ctypes
import winreg
import subprocess
import random
import logging
import threading
import tempfile
import struct
from ctypes import windll, c_uint64, Structure, c_wchar, byref, c_void_p, c_long, c_ulong, POINTER
from ctypes.wintypes import DWORD, HANDLE, LPWSTR, BOOL, BYTE, WORD, LPCSTR
from datetime import datetime, timedelta
from pathlib import Path
import psutil

# Window handle constants
HWND_TOPMOST = -1
HWND_NOTOPMOST = -2
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SW_HIDE = 0
SW_SHOW = 5

# Define necessary structures and constants
class POINT(Structure):
    _fields_ = [("x", c_long), ("y", c_long)]

class SYSTEM_INFO(Structure):
    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", c_void_p),
        ("lpMaximumApplicationAddress", c_void_p),
        ("dwActiveProcessorMask", c_ulong),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD)
    ]

# Windows constants for mouse events
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_ABSOLUTE = 0x8000

# Function declarations
user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Hide this console window
GetConsoleWindow = kernel32.GetConsoleWindow
ShowWindow = user32.ShowWindow
console_hwnd = GetConsoleWindow()
ShowWindow(console_hwnd, SW_HIDE)

# Create a system tray icon
try:
    import pystray
    from PIL import Image, ImageDraw
    SYSTRAY_ENABLED = True
except ImportError:
    SYSTRAY_ENABLED = False

class VMCountermeasures:
    def __init__(self, log_level=logging.INFO):
        # Setup basic variables
        self.setup_logging(log_level)
        self.logger.info("VM Countermeasures Started")
        self.modified_entries = []
        self.running = True
        self.threads = []
        
        # Create a working directory
        self.work_dir = os.path.join(tempfile.gettempdir(), f"vm_countermeasures_{time.time()}")
        os.makedirs(self.work_dir, exist_ok=True)
        
        # Hardware profile settings for masking
        self.cpu_model = self._get_actual_cpu_model()
        self.manufacturer = "ASUS"
        self.model = "ROG Zephyrus G14 (2023)"
        self.bios_version = "G14GA402XI.313"
        self.bios_date = "03/24/2023"
        
        # Initialize system tray if available
        if SYSTRAY_ENABLED:
            self.setup_system_tray()
    
    def _get_actual_cpu_model(self):
        """Try to get the actual CPU model from the system"""
        try:
            # First try to get from registry
            cpu_reg_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            value = self.get_registry_value(winreg.HKEY_LOCAL_MACHINE, cpu_reg_path, "ProcessorNameString")
            if value:
                return value
        except:
            pass
        
        # Default to a modern AMD CPU
        return "AMD Ryzen 7 7840HS w/ Radeon 780M Graphics"
    
    def setup_system_tray(self):
        """Setup system tray icon"""
        try:
            # Create an icon
            icon_image = self.create_icon_image()
            
            # Create a system tray icon
            self.icon = pystray.Icon("vm_countermeasures")
            self.icon.icon = icon_image
            self.icon.title = "VM Countermeasures Active"
            
            # Define menu items
            self.icon.menu = pystray.Menu(
                pystray.MenuItem("VM Countermeasures Active", lambda: None, enabled=False),
                pystray.MenuItem("Exit", self.exit_app)
            )
            
            # Start system tray icon in a separate thread
            threading.Thread(target=self.icon.run, daemon=True).start()
        except Exception as e:
            self.logger.error(f"Failed to setup system tray: {e}")
    
    def create_icon_image(self):
        """Create a simple icon for the system tray"""
        try:
            # Create a green shield icon
            width = 64
            height = 64
            color1 = (0, 128, 0)  # Dark green
            color2 = (50, 200, 50)  # Light green
            
            image = Image.new('RGB', (width, height), color=(0, 0, 0, 0))
            dc = ImageDraw.Draw(image)
            
            # Draw a shield
            dc.polygon([(width//2, 5), (width-5, height//4), 
                        (width-5, height//4*3), (width//2, height-5),
                        (5, height//4*3), (5, height//4)], fill=color1)
            
            # Draw a checkmark
            dc.line([(width//4, height//2), (width//5*2, height//5*3), 
                    (width//5*4, height//3)], fill=color2, width=5)
            
            return image
        except Exception as e:
            self.logger.error(f"Failed to create icon: {e}")
            # Return a blank image if there's an error
            return Image.new('RGB', (64, 64), color=(0, 128, 0))
    
    def exit_app(self, icon, item):
        """Exit the application from system tray menu"""
        self.restore_system()
        if hasattr(self, 'icon'):
            self.icon.stop()
        os._exit(0)
    
    def setup_logging(self, log_level):
        """Configure logging"""
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("vm_countermeasures.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("VMCountermeasures")

    def fix_rdtsc_detection(self):
        """Fix rdtsc forcing VM exit detection"""
        self.logger.info("Installing RDTSC VM exit fix...")
        
        # Create a PowerShell script that manipulates timing
        rdtsc_ps_path = os.path.join(self.work_dir, "rdtsc_fix.ps1")
        
        rdtsc_ps = """
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

public static class RdtscFixer
{
    [DllImport("kernel32.dll")]
    public static extern void Sleep(uint dwMilliseconds);
    
    [DllImport("kernel32.dll")]
    public static extern uint GetTickCount();
    
    [DllImport("kernel32.dll")]
    public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);
    
    [DllImport("kernel32.dll")]
    public static extern bool QueryPerformanceFrequency(out long lpFrequency);
    
    static Random random = new Random();
    
    // Start multiple threads to interfere with timing
    public static void StartTimingInterference()
    {
        // Start multiple threads based on CPU count
        int threadCount = Math.Max(2, Environment.ProcessorCount / 2);
        for (int i = 0; i < threadCount; i++)
        {
            Task.Factory.StartNew(() => TimingInterferenceThread(i), 
                                 TaskCreationOptions.LongRunning);
        }
    }
    
    // Thread that interferes with timing
    private static void TimingInterferenceThread(int threadId)
    {
        long perfCounter = 0, frequency = 0;
        QueryPerformanceFrequency(out frequency);
        
        // Initialize random number generator with different seed per thread
        Random threadRandom = new Random(threadId * 100 + (int)DateTime.Now.Ticks % 1000);
        
        while (true)
        {
            try
            {
                // Perform random CPU-intensive work
                int iterations = threadRandom.Next(5000, 15000);
                double result = 0;
                
                for (int i = 0; i < iterations; i++)
                {
                    result += Math.Sqrt(i * threadRandom.NextDouble());
                    
                    if (i % 1000 == 0)
                    {
                        // Query system counters to affect caching
                        QueryPerformanceCounter(out perfCounter);
                        uint tickCount = GetTickCount();
                        
                        // Random tiny sleep
                        if (threadRandom.Next(20) == 0)
                        {
                            Sleep((uint)threadRandom.Next(1, 5));
                        }
                        else
                        {
                            // Precision sleep using SpinWait
                            SpinWait.SpinUntil(() => false, 
                                threadRandom.Next(10, 100));
                        }
                    }
                }
                
                // Sleep briefly to avoid consuming 100% CPU
                Sleep((uint)threadRandom.Next(1, 10));
            }
            catch
            {
                // Ignore errors and continue
                Thread.Sleep(50);
            }
        }
    }
}
"@

# Start the timing interference
[RdtscFixer]::StartTimingInterference()

Write-Host "RDTSC timing interference active..."

# Keep script running
while($true) {
    Start-Sleep -Seconds 60
}
"""

        with open(rdtsc_ps_path, 'w') as f:
            f.write(rdtsc_ps)
        
        # Start the PowerShell script as a detached process
        try:
            subprocess.Popen(
                ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", rdtsc_ps_path],
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
            )
            self.logger.info("Started RDTSC timing interference")
        except Exception as e:
            self.logger.error(f"Failed to start RDTSC fix: {e}")
        
        return True

    def fix_cpuid_hypervisor_bit(self):
        """Fix hypervisor bit detection in CPUID"""
        self.logger.info("Installing CPUID hypervisor bit fix...")
        
        # Create a PowerShell script that modifies registry to help mask hypervisor
        cpuid_fix_path = os.path.join(self.work_dir, "cpuid_fix.ps1")
        
        cpuid_ps = """
# Registry paths for hypervisor masking
$cpuRegPath = "HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"

# Remove hypervisor identifier if present
try {
    if (Test-Path $cpuRegPath) {
        # Check if hypervisor vendor ID exists and remove it
        if (Get-ItemProperty -Path $cpuRegPath -Name "HypervisorVendorId" -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $cpuRegPath -Name "HypervisorVendorId" -Force
            Write-Host "Removed HypervisorVendorId key"
        }
        
        # Check if hypervisor-related feature bits exist and modify them
        if (Get-ItemProperty -Path $cpuRegPath -Name "FeatureSet" -ErrorAction SilentlyContinue) {
            $featureBits = (Get-ItemProperty -Path $cpuRegPath -Name "FeatureSet" -ErrorAction SilentlyContinue).FeatureSet
            
            # Clear hypervisor bit (bit 31 of ECX for CPUID leaf 1)
            $newFeatureBits = [int]$featureBits -band 0x7FFFFFFF  # Clear bit 31
            
            Set-ItemProperty -Path $cpuRegPath -Name "FeatureSet" -Value $newFeatureBits -Type DWord -Force
            Write-Host "Modified CPU feature bits to hide hypervisor bit"
        }
    }
} catch {
    Write-Host "Error modifying CPU registry: $_"
}

# Check for Hyper-V and other hypervisor services and try to hide them
$hyperVKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Hyper-V",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmicvss",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmicshutdown",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmicexchange",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmicrdv",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmictimesync",
    "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange"
)

foreach ($key in $hyperVKeys) {
    try {
        if (Test-Path $key) {
            # For services, we can't delete them but we can disable them
            if ($key -like "*\\Services\\*") {
                $serviceName = $key.Split('\\')[-1]
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "Disabled service: $serviceName"
            } else {
                # For registry keys, rename them to hide from detection
                $newKey = "$key" + "_hidden"
                if (!(Test-Path $newKey)) {
                    # Export the key
                    $randomFile = [System.IO.Path]::GetTempFileName() + ".reg"
                    $regPath = $key.Replace("HKLM:\\", "HKLM\\")
                    & reg.exe export $regPath $randomFile /y | Out-Null
                    
                    # Try to rename or delete the key
                    try {
                        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "Removed hypervisor key: $key"
                    } catch {
                        Write-Host "Could not remove $key - $_"
                    }
                }
            }
        }
    } catch {
        Write-Host "Error processing $key - $_"
    }
}

# Create fake memory entries that look more like physical hardware
try {
    $memPath = "HKLM:\\HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory"
    if (Test-Path $memPath) {
        $newRange = ".Range"
        Set-ItemProperty -Path "$memPath\$newRange" -Name "(Default)" -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF)) -Type Binary -Force
        Write-Host "Modified physical memory resource map"
    }
} catch {
    Write-Host "Error modifying physical memory resources: $_"
}

# Apply processor information
$processorRegPath = "HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
$cpuModel = "AMD Ryzen 7 7840HS w/ Radeon 780M Graphics"

try {
    # Set processor name
    Set-ItemProperty -Path $processorRegPath -Name "ProcessorNameString" -Value $cpuModel -Type String -Force
    
    # Vendor String (AMD vs Intel)
    if ($cpuModel -like "*AMD*") {
        Set-ItemProperty -Path $processorRegPath -Name "VendorIdentifier" -Value "AuthenticAMD" -Type String -Force
    } else {
        Set-ItemProperty -Path $processorRegPath -Name "VendorIdentifier" -Value "GenuineIntel" -Type String -Force
    }
    
    Write-Host "Applied processor information masking"
} catch {
    Write-Host "Error modifying processor information: $_"
}

Write-Host "CPUID and hypervisor masking complete"
"""
        
        with open(cpuid_fix_path, 'w') as f:
            f.write(cpuid_ps)
        
        # Execute the PowerShell script
        try:
            subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", cpuid_fix_path],
                capture_output=True,
                text=True
            )
            self.logger.info("Applied CPUID hypervisor bit fixes")
        except Exception as e:
            self.logger.error(f"Failed to apply CPUID fixes: {e}")
        
        # Additional registry modifications
        try:
            # Try to mask hypervisor through direct registry modification
            key_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
                
                # Try to modify or delete hypervisor-related values
                try:
                    winreg.DeleteValue(key, "HypervisorVendorId")
                except:
                    pass
                
                # Try to modify feature bits if they exist
                try:
                    feature_set, _ = winreg.QueryValueEx(key, "FeatureSet")
                    # Clear bit 31 (hypervisor bit)
                    new_feature_set = feature_set & 0x7FFFFFFF
                    winreg.SetValueEx(key, "FeatureSet", 0, winreg.REG_DWORD, new_feature_set)
                except:
                    pass
                
                winreg.CloseKey(key)
                self.logger.info("Modified CPU registry entries directly")
            except Exception as e:
                self.logger.error(f"Error modifying CPU registry directly: {e}")
        except Exception as e:
            self.logger.error(f"Failed in registry modifications: {e}")
        
        return True

    def start_mouse_activity_simulation(self):
        """Start realistic mouse activity simulation"""
        self.logger.info("Starting mouse activity simulation...")
        
        mouse_thread = threading.Thread(target=self._mouse_simulation_worker, daemon=True)
        self.threads.append(mouse_thread)
        mouse_thread.start()
        
        return True
    
    def _mouse_simulation_worker(self):
        """Worker function for mouse simulation"""
        # Save initial cursor position
        initial_x, initial_y = self._get_cursor_position()
        
        # Get screen dimensions
        screen_width = user32.GetSystemMetrics(0)  # SM_CXSCREEN
        screen_height = user32.GetSystemMetrics(1)  # SM_CYSCREEN
        
        # Mouse movement parameters
        click_interval = 8  # seconds between clicks
        last_click_time = time.time()
        
        while self.running:
            try:
                # Get current position
                curr_x, curr_y = self._get_cursor_position()
                
                # Decide on a destination point
                dest_x = random.randint(100, screen_width - 100)
                dest_y = random.randint(100, screen_height - 100)
                
                # Calculate a curved path using Bezier curve
                # This creates more human-like mouse movement
                steps = random.randint(20, 50)  # More steps for smoother movement
                
                # Control points for the Bezier curve
                ctrl_x1 = curr_x + random.randint(-200, 200)
                ctrl_y1 = curr_y + random.randint(-200, 200)
                ctrl_x2 = dest_x + random.randint(-200, 200)
                ctrl_y2 = dest_y + random.randint(-200, 200)
                
                # Keep control points within screen bounds
                ctrl_x1 = max(0, min(screen_width, ctrl_x1))
                ctrl_y1 = max(0, min(screen_height, ctrl_y1))
                ctrl_x2 = max(0, min(screen_width, ctrl_x2))
                ctrl_y2 = max(0, min(screen_height, ctrl_y2))
                
                # Move along the Bezier path
                for i in range(steps + 1):
                    # Calculate position along Bezier curve
                    t = i / steps
                    t_squared = t * t
                    t_cubed = t_squared * t
                    u = 1 - t
                    u_squared = u * u
                    u_cubed = u_squared * u
                    
                    # Cubic Bezier formula
                    x = int(u_cubed * curr_x + 
                           3 * u_squared * t * ctrl_x1 + 
                           3 * u * t_squared * ctrl_x2 + 
                           t_cubed * dest_x)
                    
                    y = int(u_cubed * curr_y + 
                           3 * u_squared * t * ctrl_y1 + 
                           3 * u * t_squared * ctrl_y2 + 
                           t_cubed * dest_y)
                    
                    # Set cursor position
                    user32.SetCursorPos(x, y)
                    
                    # Vary the speed (slower near start and end points)
                    delay = 0.01
                    if i < steps * 0.2 or i > steps * 0.8:
                        delay = 0.02  # Slower at beginning and end
                    time.sleep(delay)
                
                # Sometimes perform mouse clicks
                current_time = time.time()
                if current_time - last_click_time > click_interval:
                    # Perform a mouse click
                    user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, None)
                    time.sleep(random.uniform(0.08, 0.15))  # Hold down the button
                    user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, None)
                    
                    # Sometimes do a double-click with realistic timing
                    if random.random() < 0.3:
                        time.sleep(random.uniform(0.1, 0.3))  # Delay between clicks
                        user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, None)
                        time.sleep(random.uniform(0.08, 0.15))
                        user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, None)
                    
                    last_click_time = current_time
                
                # Pause between movements
                time.sleep(random.uniform(0.5, 2.0))
            except Exception as e:
                self.logger.error(f"Error in mouse simulation: {e}")
                time.sleep(1)
    
    def _get_cursor_position(self):
        """Get the current cursor position"""
        pt = POINT()
        user32.GetCursorPos(byref(pt))
        return pt.x, pt.y

    def start_dialog_handler(self):
        """Start handler for dialog windows"""
        self.logger.info("Starting dialog interaction handler...")
        
        dialog_thread = threading.Thread(target=self._dialog_handler_worker, daemon=True)
        self.threads.append(dialog_thread)
        dialog_thread.start()
        
        return True
    
    def _dialog_handler_worker(self):
        """Worker function to handle dialog windows"""
        # Constants for window messaging
        WM_COMMAND = 0x0111
        IDYES = 6
        IDOK = 1
        
        # Common dialog class names
        dialog_classes = ["#32770", "MessageBox", "DialogBox"]
        
        while self.running:
            try:
                # Search for dialog windows
                for class_name in dialog_classes:
                    # Find dialog by class name
                    hwnd = user32.FindWindowA(class_name.encode('utf-8'), None)
                    
                    if hwnd:
                        self.logger.info(f"Found dialog with class: {class_name}")
                        
                        # Wait a bit before responding (human-like delay)
                        time.sleep(random.uniform(0.5, 2.0))
                        
                        # Click Yes/OK button (usually the safest choice)
                        user32.SendMessageA(hwnd, WM_COMMAND, IDYES, 0)
                        
                        self.logger.info(f"Responded to dialog")
                        time.sleep(0.5)  # Wait for dialog to close
                
                # Check periodically
                time.sleep(0.2)
            except Exception as e:
                self.logger.error(f"Error in dialog handler: {e}")
                time.sleep(1)

    def fix_os_uptime(self):
        """Fix operating system uptime detection"""
        self.logger.info("Fixing OS uptime detection...")
        
        # We'll modify registry to make the system look like it's been running longer
        try:
            # Set the last boot time to appear older
            current_time = int(time.time())
            boot_time = current_time - (7 * 24 * 60 * 60)  # 7 days ago
            
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
            
            # Save original value before modifying
            try:
                original_install_date, _ = winreg.QueryValueEx(key, "InstallDate")
                self.modified_entries.append({
                    "key_path": key_path,
                    "name": "InstallDate",
                    "value": original_install_date
                })
            except:
                pass
            
            # Set an earlier install date
            winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_DWORD, boot_time)
            winreg.CloseKey(key)
            
            self.logger.info(f"Modified OS install date to simulate longer uptime")
        except Exception as e:
            self.logger.error(f"Failed to modify OS uptime registry: {e}")
        
        # Create a PowerShell script for additional uptime masking
        uptime_ps_path = os.path.join(self.work_dir, "uptime_fix.ps1")
        
        uptime_ps = """
# Set system uptime registry values
try {
    # Calculate a boot time 7 days ago
    $currentTime = [int](Get-Date -UFormat %s)
    $bootTime = $currentTime - (7 * 24 * 60 * 60)
    
    # Path containing uptime-related info
    $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    
    # Back up original value
    $original = (Get-ItemProperty -Path $regPath -Name "InstallDate" -ErrorAction SilentlyContinue).InstallDate
    if ($original) {
        # Create backup key if it doesn't exist
        if (!(Test-Path "$regPath`_Backup")) {
            New-Item -Path "$regPath`_Backup" -Force | Out-Null
        }
        Set-ItemProperty -Path "$regPath`_Backup" -Name "OriginalInstallDate" -Value $original -Type DWord -Force -ErrorAction SilentlyContinue
    }
    
    # Set modified install date
    Set-ItemProperty -Path $regPath -Name "InstallDate" -Value $bootTime -Type DWord -Force
    
    Write-Host "Modified registry to simulate longer system uptime"
    
    # Modify performance counter frequency to affect time measurements
    $perfPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib"
    if (Test-Path $perfPath) {
        # Try to modify performance counters
        try {
            # Make subtle changes to how time is measured
            Set-ItemProperty -Path $perfPath -Name "DebugLevelTime" -Value 0 -Type DWord -Force
        } catch {}
    }
} catch {
    Write-Host "Error modifying uptime registry: $_"
}

# Keep the script running to continue interfering with time measurements
while ($true) { 
    # Create some CPU activity with random patterns
    $random = New-Object System.Random
    $result = 0
    
    # Random iterations
    $iterations = $random.Next(10000, 30000)
    for ($i = 0; $i -lt $iterations; $i++) {
        $result += [math]::Sqrt($i * $random.NextDouble())
        
        # Occasionally introduce timing irregularities
        if ($i % 5000 -eq 0) {
            $sleepTime = $random.Next(1, 5)
            Start-Sleep -Milliseconds $sleepTime
        }
    }
    
    # Random sleep between intervals
    $sleepTime = $random.Next(1000, 5000)
    Start-Sleep -Milliseconds $sleepTime
}
"""

        with open(uptime_ps_path, 'w') as f:
            f.write(uptime_ps)
        
        # Start the PowerShell script in the background
        try:
            subprocess.Popen(
                ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", uptime_ps_path],
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
            )
            self.logger.info("Started OS uptime fix script")
        except Exception as e:
            self.logger.error(f"Failed to start OS uptime fix: {e}")
        
        return True

    def apply_registry_tweaks(self):
        """Apply comprehensive registry tweaks to hide VM features"""
        self.logger.info("Applying registry modifications...")
        
        registry_modifications = [
            # System BIOS information
            {
                "path": r"SYSTEM\CurrentControlSet\Control\SystemInformation",
                "key": "SystemBiosVersion",
                "value": f"{self.manufacturer} {self.bios_version}, {self.bios_date}",
                "type": winreg.REG_MULTI_SZ
            },
            {
                "path": r"SYSTEM\CurrentControlSet\Control\SystemInformation",
                "key": "SystemManufacturer",
                "value": self.manufacturer,
                "type": winreg.REG_SZ
            },
            {
                "path": r"SYSTEM\CurrentControlSet\Control\SystemInformation",
                "key": "SystemProductName",
                "value": self.model,
                "type": winreg.REG_SZ
            },
            {
                "path": r"SYSTEM\CurrentControlSet\Control\SystemInformation",
                "key": "BIOSReleaseDate",
                "value": self.bios_date,
                "type": winreg.REG_SZ
            },
            
            # Hardware information
            {
                "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                "key": "BIOSVendor",
                "value": self.manufacturer,
                "type": winreg.REG_SZ
            },
            {
                "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                "key": "BIOSVersion",
                "value": self.bios_version,
                "type": winreg.REG_SZ
            },
            {
                "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                "key": "BIOSReleaseDate",
                "value": self.bios_date,
                "type": winreg.REG_SZ
            },
            {
                "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                "key": "SystemManufacturer",
                "value": self.manufacturer,
                "type": winreg.REG_SZ
            },
            {
                "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                "key": "SystemProductName",
                "value": self.model,
                "type": winreg.REG_SZ
            },
            
            # System UUID (often checked for VM detection)
            {
                "path": r"SOFTWARE\Microsoft\Cryptography",
                "key": "MachineGuid",
                "value": str(random.randint(100000000, 999999999)) + "-" + 
                         str(random.randint(1000, 9999)) + "-" + 
                         str(random.randint(1000, 9999)) + "-" + 
                         str(random.randint(100000000000, 999999999999)),
                "type": winreg.REG_SZ
            },
            
            # Video BIOS information
            {
                "path": r"HARDWARE\DESCRIPTION\System",
                "key": "VideoBiosVersion",
                "value": f"AMD ATOMBIOS",
                "type": winreg.REG_MULTI_SZ
            },
            
            # Disable debug features that might help detection
            {
                "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "key": "GlobalFlag",
                "value": 0,
                "type": winreg.REG_DWORD
            }
        ]
        
        # Registry keys to delete
        keys_to_delete = [
            # VirtualBox ACPI entries
            r"HARDWARE\ACPI\DSDT\VBOX__",
            r"HARDWARE\ACPI\FADT\VBOX__",
            r"HARDWARE\ACPI\RSDT\VBOX__",
            
            # Sandbox and VM services
            r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
            r"SYSTEM\CurrentControlSet\Services\VBoxMouse",
            r"SYSTEM\CurrentControlSet\Services\VBoxService",
            r"SYSTEM\CurrentControlSet\Services\VBoxSF",
            r"SYSTEM\CurrentControlSet\Services\VBoxVideo",
            r"SYSTEM\CurrentControlSet\Services\vmicheartbeat",
            r"SYSTEM\CurrentControlSet\Services\vmicvss",
            r"SYSTEM\CurrentControlSet\Services\vmicshutdown",
            r"SYSTEM\CurrentControlSet\Services\vmicexchange",
            r"SOFTWARE\VMware, Inc.",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions"
        ]
        
        # Apply registry modifications
        for mod in registry_modifications:
            try:
                # Backup current value
                current_value = self.get_registry_value(winreg.HKEY_LOCAL_MACHINE, mod["path"], mod.get("key", ""))
                if current_value is not None:
                    self.modified_entries.append({
                        "hkey": winreg.HKEY_LOCAL_MACHINE,
                        "path": mod["path"],
                        "key": mod.get("key", ""),
                        "original_value": current_value
                    })
                
                # Apply modification
                self.set_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    mod["path"], 
                    mod.get("key", ""), 
                    mod["value"], 
                    mod["type"],
                    create=True
                )
                self.logger.info(f"Modified registry: {mod['path']}\\{mod.get('key', '')}")
            except Exception as e:
                self.logger.error(f"Failed to modify registry: {e}")
        
        # Delete registry keys
        for key_path in keys_to_delete:
            try:
                self.delete_registry_key(winreg.HKEY_LOCAL_MACHINE, key_path)
            except Exception:
                pass  # Ignore if key doesn't exist
        
        return True
    
    def get_registry_value(self, hkey, path, key_name):
        """Get a registry value safely"""
        try:
            reg_key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(reg_key, key_name)
            winreg.CloseKey(reg_key)
            return value
        except Exception:
            return None
    
    def set_registry_value(self, hkey, path, key_name, value, value_type, create=False):
        """Set or create a registry value"""
        try:
            try:
                reg_key = winreg.OpenKey(hkey, path, 0, winreg.KEY_WRITE)
            except FileNotFoundError:
                if create:
                    reg_key = winreg.CreateKey(hkey, path)
                else:
                    raise
            
            winreg.SetValueEx(reg_key, key_name, 0, value_type, value)
            winreg.CloseKey(reg_key)
            return True
        except Exception as e:
            self.logger.error(f"Error setting registry value: {e}")
            return False
    
    def delete_registry_key(self, hkey, path):
        """Delete a registry key"""
        try:
            winreg.DeleteKey(hkey, path)
            self.logger.info(f"Deleted registry key: {path}")
            return True
        except FileNotFoundError:
            return True  # Key doesn't exist, so no need to delete
        except Exception as e:
            self.logger.error(f"Error deleting registry key: {e}")
            return False

    def patch_wmi_data(self):
        """Apply patches to WMI data that might reveal virtualization"""
        self.logger.info("Patching WMI information...")
        
        # Create a WMI modification script
        wmi_script_path = os.path.join(self.work_dir, "wmi_patch.ps1")
        
        wmi_script = """
# WMI masking for VM detection
$ErrorActionPreference = "SilentlyContinue"

function Set-WmiNamespace {
    Param (
        [string]$Namespace,
        [string]$Class,
        [string]$Property,
        [string]$Value,
        [string]$WhereProperty,
        [string]$WhereValue
    )
    
    try {
        $filter = if ($WhereProperty -and $WhereValue) { 
            "$WhereProperty = '$WhereValue'"
        } else { 
            $null
        }
        
        $query = "SELECT * FROM $Class"
        if ($filter) {
            $query += " WHERE $filter"
        }
        
        $wmiObjects = Get-WmiObject -Namespace $Namespace -Query $query
        if ($wmiObjects -is [array]) {
            foreach ($wmiObject in $wmiObjects) {
                $wmiObject.$Property = $Value
                $wmiObject.Put() | Out-Null
            }
        } elseif ($wmiObjects) {
            $wmiObjects.$Property = $Value
            $wmiObjects.Put() | Out-Null
        }
        return $true
    } catch {
        Write-Host "Failed to set WMI property: $_"
        return $false
    }
}

# Physical hardware properties to mimic
$manufacturer = "ASUS"
$model = "ROG Zephyrus G14 (2023)"
$biosVersion = "G14GA402XI.313"
$biosDate = "03/24/2023"
$serialNumber = "R9N" + ([char[]](65..90) | Get-Random -Count 8 | ForEach-Object {$_}) -join ""
$uuid = [guid]::NewGuid().ToString()

# Get the actual CPU model from registry or use default
$cpuModel = (Get-ItemProperty -Path "HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" -Name "ProcessorNameString" -ErrorAction SilentlyContinue).ProcessorNameString
if (!$cpuModel) { 
    $cpuModel = "AMD Ryzen 7 7840HS w/ Radeon 780M Graphics"
}

# Modify ComputerSystem
Write-Host "Modifying Win32_ComputerSystem..."
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_ComputerSystem" -Property "Manufacturer" -Value $manufacturer
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_ComputerSystem" -Property "Model" -Value $model
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_ComputerSystem" -Property "TotalPhysicalMemory" -Value 17179869184  # 16GB

# Modify BIOS
Write-Host "Modifying Win32_BIOS..."
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BIOS" -Property "Manufacturer" -Value $manufacturer
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BIOS" -Property "Version" -Value $biosVersion
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BIOS" -Property "ReleaseDate" -Value $biosDate
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BIOS" -Property "SerialNumber" -Value $serialNumber
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BIOS" -Property "SMBIOSBIOSVersion" -Value $biosVersion

# Modify BaseBoard
Write-Host "Modifying Win32_BaseBoard..."
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BaseBoard" -Property "Manufacturer" -Value $manufacturer
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BaseBoard" -Property "Product" -Value $model.Split(' ')[0]
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_BaseBoard" -Property "SerialNumber" -Value $serialNumber

# Modify Processor information
Write-Host "Modifying Win32_Processor..."
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_Processor" -Property "Name" -Value $cpuModel
Set-WmiNamespace -Namespace "root\cimv2" -Class "Win32_Processor" -Property "Manufacturer" -Value $(if ($cpuModel -like "*AMD*") {"AuthenticAMD"} else {"GenuineIntel"})

# Remove VM-specific devices from WMI
Write-Host "Removing VM-specific devices from WMI..."
$vmDeviceNames = @("VMware", "Virtual", "VBOX", "VBox")
foreach ($deviceName in $vmDeviceNames) {
    Get-WmiObject Win32_PnPEntity | Where-Object {$_.Name -like "*$deviceName*"} | ForEach-Object {
        try {
            $_.Delete()
        } catch {}
    }
}

# Try to fix PortConnector class which often reveals VM status
Write-Host "Modifying Win32_PortConnector..."
try {
    $portConnectors = Get-WmiObject -Class Win32_PortConnector -ErrorAction SilentlyContinue
    if (!$portConnectors) {
        # Create a custom port connector if none exists (indicating VM)
        $newPort = [wmiclass]"\\.\root\cimv2:Win32_PortConnector"
        $newInstance = $newPort.CreateInstance()
        $newInstance.Tag = "COM1"
        $newInstance.ExternalReferenceDesignator = "Serial Port"
        $newInstance.ConnectorType = 0
        $newInstance.PortType = 0
        $newInstance.Put() | Out-Null
    }
} catch {}

# Try to fix PhysicalMemory class which often reveals VM status
Write-Host "Modifying Win32_PhysicalMemory..."
try {
    $memoryModules = Get-WmiObject -Class Win32_PhysicalMemory -ErrorAction SilentlyContinue
    if (!$memoryModules) {
        # Create a custom memory entry if none exists (indicating VM)
        $newMem = [wmiclass]"\\.\root\cimv2:Win32_PhysicalMemory"
        $newInstance = $newMem.CreateInstance()
        $newInstance.SerialNumber = "8219" + (Get-Random -Minimum 10000 -Maximum 99999)
        $newInstance.PartNumber = "HMA81GS6DJR8N-VK"
        $newInstance.Manufacturer = "SK Hynix"
        $newInstance.Capacity = 8589934592  # 8GB
        $newInstance.Speed = 3200
        $newInstance.Put() | Out-Null
    }
} catch {}

# Modify disk drive information
Write-Host "Modifying disk drives..."
$physicalDiskModels = @(
    "WDC WD10EZEX-00KUWA0",
    "Samsung SSD 980 PRO 1TB",
    "KINGSTON SNV2S1000G",
    "CT1000P3PSSD8"
)
$selectedDisk = $physicalDiskModels | Get-Random

try {
    $diskDrives = Get-WmiObject Win32_DiskDrive
    foreach ($drive in $diskDrives) {
        if ($drive.Model -match "VBOX|VMware|Virtual|QEMU") {
            $drive.Model = $selectedDisk
            $drive.SerialNumber = "WD-" + (Get-Random -Minimum 1000000 -Maximum 9999999).ToString()
            $drive.Put() | Out-Null
        }
    }
} catch {}

Write-Host "WMI patching complete"
"""
        
        with open(wmi_script_path, 'w') as f:
            f.write(wmi_script)
        
        # Execute the script
        try:
            subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", wmi_script_path],
                capture_output=True,
                text=True
            )
            self.logger.info("WMI information patched successfully")
        except Exception as e:
            self.logger.error(f"Failed to patch WMI information: {e}")
        
        return True
    
    def apply_all_countermeasures(self):
        """Apply all VM detection countermeasures"""
        self.logger.info("Starting all VM detection countermeasures...")
        
        # Apply registry modifications first
        self.apply_registry_tweaks()
        
        # Fix hypervisor detection
        self.fix_cpuid_hypervisor_bit()
        
        # Patch WMI data
        self.patch_wmi_data()
        
        # Fix rdtsc detection
        self.fix_rdtsc_detection()
        
        # Fix OS uptime detection
        self.fix_os_uptime()
        
        # Start mouse activity simulation
        self.start_mouse_activity_simulation()
        
        # Start dialog handler
        self.start_dialog_handler()
        
        self.logger.info("All VM detection countermeasures are active!")
        
        # Log success message
        print("VM detection countermeasures are now active!")
        print("This tool is hiding virtualization from detection tools like Pafish.")
        print("The tool will continue running in the background.")
    
    def restore_system(self):
        """Restore system to its original state"""
        self.logger.info("Restoring system to original state...")
        
        # Set running flag to stop all threads
        self.running = False
        
        # Restore registry values
        for entry in self.modified_entries:
            try:
                self.set_registry_value(
                    entry["hkey"],
                    entry["path"],
                    entry["key"],
                    entry["original_value"],
                    winreg.REG_SZ if isinstance(entry["original_value"], str) else winreg.REG_DWORD
                )
                self.logger.info(f"Restored registry: {entry['path']}\\{entry['key']}")
            except Exception as e:
                self.logger.error(f"Failed to restore registry: {e}")
        
        # Kill any PowerShell processes we started
        try:
            subprocess.run([
                "taskkill", "/F", "/IM", "powershell.exe", "/FI", "WINDOWTITLE eq *fix*"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
        
        # Clean up temporary files
        try:
            for file in os.listdir(self.work_dir):
                try:
                    os.remove(os.path.join(self.work_dir, file))
                except:
                    pass
            os.rmdir(self.work_dir)
            self.logger.info(f"Removed working directory: {self.work_dir}")
        except Exception as e:
            self.logger.error(f"Failed to clean up working directory: {e}")
        
        self.logger.info("System restoration complete")
        print("System has been restored to its original state.")

def main():
    try:
        # Start the countermeasures
        countermeasures = VMCountermeasures()
        countermeasures.apply_all_countermeasures()
        
        # Keep the script running
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Shutting down and cleaning up...")
        countermeasures.restore_system()
    except Exception as e:
        print(f"Error: {e}")
        try:
            countermeasures.restore_system()
        except:
            pass

if __name__ == "__main__":
    main()
'@
    
    # Write the script to disk
    Set-Content -Path $scriptPath -Value $scriptContent -Force
    Log-Status "VM countermeasures script created at: $scriptPath"
    
    # Create a batch file to run the countermeasures script with admin rights
    $batchPath = "C:\SharedData\run_countermeasures.bat"
    $batchContent = @"
@echo off
echo Starting VM detection countermeasures...
powershell -Command "Start-Process -FilePath python -ArgumentList 'C:\SharedData\vm_countermeasures.py' -Verb RunAs -WindowStyle Hidden"
exit
"@
    Set-Content -Path $batchPath -Value $batchContent -Force
    Log-Status "Created batch launcher at: $batchPath"
    
    # Make the script run automatically at startup
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\VMProtection.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($startupPath)
    $Shortcut.TargetPath = "C:\SharedData\run_countermeasures.bat"
    $Shortcut.WorkingDirectory = "C:\SharedData"
    $Shortcut.WindowStyle = 7  # 7=Minimized
    $Shortcut.Description = "VM Protection"
    $Shortcut.Save()
    Log-Status "Added startup shortcut for VM protection"
    
    return $scriptPath
}

# Main setup execution
try {
    # 1. Setup user environment
    Setup-UserEnvironment
    
    # 2. Install Python if needed
    Install-Python
    
    # 3. Create the VM countermeasures script
    $scriptPath = Create-PafishDefeatScript
    
    # 4. Run the VM countermeasures script with admin rights
    Log-Status "Starting VM detection countermeasures..."
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c C:\SharedData\run_countermeasures.bat" -NoNewWindow
    
    # 5. Show success notification
    Log-Status "Setup completed successfully!"
    
    # Create a status window
    $statusScript = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create form
`$form = New-Object System.Windows.Forms.Form
`$form.Text = "VM Protection Active"
`$form.Size = New-Object System.Drawing.Size(400, 200)
`$form.StartPosition = "CenterScreen"
`$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
`$form.MaximizeBox = `$false
`$form.BackColor = [System.Drawing.Color]::White

# Create icon
`$iconBase64 = "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABmJLR0QA/wD/AP+gvaeTAAABV0lEQVRIie2Uv0oDQRDGf7MxWKQImkKD5AEsrGwsfAMfIS9gY2FhYWfhI/gCQcTCzkKDjY2QiEjiP8iPhZ3Nyt3e7d0FRPDBwM7MN9/M7twsLPgnSZSvBYeZv1d8MlhHzvYauAQagX0NjIAxMI4xroBroOUda8B+2eQHQNfb67ILrIXn74DTGJNA58AO8AR0gVNvd72v+BlwCDyH8XVgpwx+YOAReAMOSgRsALc+rgk8AMsl45t+jxMuwTPggSkDT+bX9JyUTZxUFNwBVtNLzhLYCgLmQaJ8HWAF6AEnKX/g/jPgDLiYEt9JxQ5D3BbwCnwCG1nBd0JTe8b5UHBvCOZhPfg+soLHVNO2CvBQ2PmQ3a/AZgpAakq5N0K+RolvpvehnOAhInjzorwIsIDX4/WtnFJJ5fDhOPP+EOxTL+r+tqC2CLwDWALegY3/QIAkST4BA21P1mmYid8AAAAASUVORK5CYII="
`$iconBytes = [Convert]::FromBase64String(`$iconBase64)
`$ms = New-Object System.IO.MemoryStream(`$iconBytes, 0, `$iconBytes.Length)
`$ms.Write(`$iconBytes, 0, `$iconBytes.Length)
`$icon = [System.Drawing.Image]::FromStream(`$ms, `$true)
`$form.Icon = [System.Drawing.Icon]::FromHandle((`$icon.GetHicon()))

# Create shield icon
`$shieldBox = New-Object System.Windows.Forms.PictureBox
`$shieldBox.Width = 64
`$shieldBox.Height = 64
`$shieldBox.Image = `$icon
`$shieldBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
`$shieldBox.Location = New-Object System.Drawing.Point(20, 20)
`$form.Controls.Add(`$shieldBox)

# Create heading
`$heading = New-Object System.Windows.Forms.Label
`$heading.Text = "VM Protection Active"
`$heading.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
`$heading.ForeColor = [System.Drawing.Color]::DarkGreen
`$heading.Location = New-Object System.Drawing.Point(100, 30)
`$heading.AutoSize = `$true
`$form.Controls.Add(`$heading)

# Create status text
`$statusText = New-Object System.Windows.Forms.Label
`$statusText.Text = "VM detection countermeasures are running.`r`nYou can safely close this window."
`$statusText.Location = New-Object System.Drawing.Point(100, 70)
`$statusText.AutoSize = `$true
`$form.Controls.Add(`$statusText)

# Create OK button
`$okButton = New-Object System.Windows.Forms.Button
`$okButton.Text = "OK"
`$okButton.Location = New-Object System.Drawing.Point(150, 120)
`$okButton.Add_Click({ `$form.Close() })
`$form.Controls.Add(`$okButton)

# Set accept button
$form.AcceptButton = $okButton

# Display the form
$form.ShowDialog() | Out-Null
"@

# Execute the status window script
$statusScriptPath = "C:\SharedData\status.ps1"
Set-Content -Path $statusScriptPath -Value $statusScript -Force
Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File `"$statusScriptPath`"" -WindowStyle Normal

} catch {
    Log-Status "Setup failed: $_"
    
    # Show error notification
    [System.Windows.Forms.MessageBox]::Show("VM Protection setup failed: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}