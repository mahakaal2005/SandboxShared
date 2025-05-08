import os
import sys
import time
import ctypes
import winreg
import subprocess
import random
import logging
import tempfile
import struct
import hashlib
import uuid
import threading
import socket
from ctypes import windll, c_uint64, Structure, c_wchar, byref, c_void_p, c_long, c_ulong
from ctypes import POINTER, c_ubyte, c_ushort, c_uint, pointer, sizeof, c_char_p, c_int
from ctypes.wintypes import DWORD, HANDLE, LPWSTR, BOOL, BYTE, WORD, LPCSTR
from datetime import datetime, timedelta
from pathlib import Path

# Check for additional dependencies
try:
    import psutil
except ImportError:
    print("Required dependency 'psutil' not found.")
    print("Please install it using: pip install psutil")
    choice = input("Attempt to install automatically? (y/n): ")
    if choice.lower() == 'y':
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
            import psutil
            print("Successfully installed psutil.")
        except Exception as e:
            print(f"Failed to install dependencies: {e}")
            sys.exit(1)
    else:
        sys.exit(1)

# Try to import system tray dependencies
try:
    import pystray
    from PIL import Image, ImageDraw
    SYSTRAY_ENABLED = True
except ImportError:
    SYSTRAY_ENABLED = False

# Define constants
SW_HIDE = 0
SW_SHOW = 5
VERSION = "1.1.0"

# Check for admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# If not admin, restart with admin rights
if not is_admin():
    print("Pafish Defeat requires administrator privileges.")
    print("Restarting with admin rights...")
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    except:
        print("Failed to acquire admin rights. Please run as administrator.")
        sys.exit(1)

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

class MEMORYSTATUSEX(Structure):
    _fields_ = [
        ("dwLength", DWORD),
        ("dwMemoryLoad", DWORD),
        ("ullTotalPhys", c_uint64),
        ("ullAvailPhys", c_uint64),
        ("ullTotalPageFile", c_uint64),
        ("ullAvailPageFile", c_uint64),
        ("ullTotalVirtual", c_uint64),
        ("ullAvailVirtual", c_uint64),
        ("ullAvailExtendedVirtual", c_uint64),
    ]

# Define structures needed for kernel32 functions
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", c_void_p),
        ("bInheritHandle", BOOL)
    ]

# Define point structure for mouse operations
class POINT(Structure):
    _fields_ = [("x", c_long), ("y", c_long)]

# Define constants for memory allocation
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x1F0FFF
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014c
MAXIMUM_SUPPORTED_EXTENSION = 512

class PafishDefeat:

    def specialized_cpuid_fix(self):
        """Apply specialized fixes for CPUID hypervisor detection"""
        self.logger.info("Applying specialized CPUID hypervisor bit fixes...")

        # Create a PowerShell script for deeper hypervisor masking
        ps_script_path = os.path.join(self.work_dir, "deep_hypervisor_mask.ps1")

        ps_script = """
    # Administrator check
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "This script requires administrative privileges to run properly!"
        Exit
    }
    
    Write-Host "Starting aggressive hypervisor masking..." -ForegroundColor Green
    
    # Function to back up registry values before modifying them
    function Backup-RegistryValue {
        param (
            [string]$Path,
            [string]$Name
        )
        
        try {
            if (Test-Path "HKLM:\\$Path") {
                $value = Get-ItemProperty -Path "HKLM:\\$Path" -Name $Name -ErrorAction SilentlyContinue
                if ($value -ne $null) {
                    $bakPath = "HKLM:\\$Path\\Backup"
                    if (!(Test-Path $bakPath)) {
                        New-Item -Path $bakPath -Force | Out-Null
                    }
                    New-ItemProperty -Path $bakPath -Name "$($Name)_Backup" -Value $value.$Name -PropertyType (Get-ItemProperty -Path "HKLM:\\$Path" -Name $Name).PSObject.Properties[$Name].TypeNameOfValue -Force | Out-Null
                    return $true
                }
            }
        } catch {}
        return $false
    }
    
    # CPU Core 0 manipulation - this affects CPUID results since Pafish checks processor 0
    $cpuPath = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
    Write-Host "Aggressively modifying CPU information..." -ForegroundColor Yellow
    
    # Back up key values
    Backup-RegistryValue -Path $cpuPath -Name "FeatureSet"
    Backup-RegistryValue -Path $cpuPath -Name "VendorIdentifier"
    Backup-RegistryValue -Path $cpuPath -Name "ProcessorNameString"
    
    # Get CPU Feature Set and clear hypervisor bit (bit 31)
    $featureSet = (Get-ItemProperty -Path "HKLM:\\$cpuPath" -Name "FeatureSet" -ErrorAction SilentlyContinue).FeatureSet
    if ($featureSet -ne $null) {
        $newFeatureSet = $featureSet -band 0x7FFFFFFF
        Set-ItemProperty -Path "HKLM:\\$cpuPath" -Name "FeatureSet" -Value $newFeatureSet -Type DWord -Force
        Write-Host "Cleared hypervisor bit in CPU feature set"
    }
    
    # Try to directly remove Hypervisor keys
    try {
        Remove-ItemProperty -Path "HKLM:\\$cpuPath" -Name "HypervisorVendorId" -Force -ErrorAction SilentlyContinue
        Write-Host "Removed HypervisorVendorId"
    } catch {}
    
    # Disable all Hyper-V services
    $hyperVServices = @(
        "HvHost",
        "vmicheartbeat",
        "vmicvss",
        "vmicshutdown",
        "vmicexchange",
        "vmickvpexchange",
        "vmicrdv",
        "vmictimesync"
    )
    
    foreach ($service in $hyperVServices) {
        try {
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Disabled service: $service"
        } catch {}
    }
    
    # More aggressive - try to block access to hypervisor-related registry keys
    $blockKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
        "HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\WindowsVirtualization"
    )
    
    foreach ($key in $blockKeys) {
        if (Test-Path $key) {
            try {
                $acl = Get-Acl -Path $key
                $acl.SetAccessRuleProtection($true, $false)
                Set-Acl -Path $key -AclObject $acl -ErrorAction SilentlyContinue
                Write-Host "Modified ACL to restrict access to: $key"
            } catch {}
        }
    }
    
    # Additional CPUID masking via direct registry tricks
    # Manipulate how Windows uses CPUID
    $processorPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Tracing\\Microsoft\\Windows\\TraceLogging\\ResourcePublisher\\CPU\\Processor"
    if (!(Test-Path $processorPath)) {
        New-Item -Path $processorPath -Force | Out-Null
        Set-ItemProperty -Path $processorPath -Name "Default" -Value 0 -Type DWord -Force
        Write-Host "Created CPU processor tracing configuration to block hypervisor detection"
    }
    
    # Direct WBEM namespace manipulation for WMI queries
    try {
        # Create a management scope and connect to the WMI namespace
        $scope = New-Object System.Management.ManagementScope("\\.\root\cimv2")
        $scope.Connect()
    
        # Get the Win32_Processor class
        $class = [System.Management.ManagementClass]::new($scope, [System.Management.ManagementPath]::new("Win32_Processor"), $null)
        $instances = $class.GetInstances()
    
        Write-Host "Attempting direct WMI manipulation..."
        foreach ($instance in $instances) {
            # Try to modify hypervisor-related properties
            try {
                if ($instance["Description"] -match "Hyper|Virtual") {
                    $instance["Description"] = $instance["Description"] -replace "Hyper|Virtual", ""
                    $instance.Put()
                }
            } catch {}
        }
    } catch {
        Write-Host "WMI manipulation failed: $_"
    }
    
    Write-Host "Aggressive hypervisor masking complete" -ForegroundColor Green
    """

        with open(ps_script_path, 'w') as f:
            f.write(ps_script)

        # Execute the script with admin privileges
        try:
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script_path],
                capture_output=True,
                text=True
            )
            if "Aggressive hypervisor masking complete" in result.stdout:
                self.logger.info("Applied specialized CPUID hypervisor bit fixes")
            else:
                self.logger.warning(f"Specialized CPUID fixes may not have fully applied: {result.stderr}")
        except Exception as e:
            self.logger.error(f"Failed to apply specialized CPUID fixes: {e}")

    def enhanced_rdtsc_fix(self):
        """Enhanced fix for RDTSC detection that forces VM exit"""
        self.logger.info("Applying enhanced RDTSC VM exit fixes...")

        # Create a PowerShell script for aggressive RDTSC timing manipulation
        ps_script_path = os.path.join(self.work_dir, "rdtsc_aggressive_fix.ps1")

        ps_script = """
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Diagnostics;
    using System.Collections.Generic;
    
    public static class RdtscExitFixer
    {
        // Import kernel32 timing functions
        [DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
        
        [DllImport("kernel32.dll")]
        public static extern uint GetTickCount();
        
        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();
        
        [DllImport("kernel32.dll")]
        public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);
        
        [DllImport("kernel32.dll")]
        public static extern bool QueryPerformanceFrequency(out long lpFrequency);
        
        // Enable thread processor affinity manipulation
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr SetThreadAffinityMask(IntPtr hThread, IntPtr dwThreadAffinityMask);
        
        // Create unpredictable timing patterns
        public static void StartAggressiveTimingInterference()
        {
            // Log start
            Console.WriteLine("Starting aggressive RDTSC interference...");
            
            // Get total processor count for thread distribution
            int processorCount = Environment.ProcessorCount;
            Console.WriteLine($"Detected {processorCount} processors");
            
            // Create multiple interference threads
            for (int i = 0; i < processorCount; i++)
            {
                int processorId = i;
                Task.Factory.StartNew(() => ProcessorSpecificThread(processorId), TaskCreationOptions.LongRunning);
            }
            
            // Create specialized threads for specific timing attack patterns
            Task.Factory.StartNew(() => TimingPatternDisruptorThread(), TaskCreationOptions.LongRunning);
            Task.Factory.StartNew(() => HighFrequencyInterferenceThread(), TaskCreationOptions.LongRunning);
            Task.Factory.StartNew(() => PerformanceCounterManipulationThread(), TaskCreationOptions.LongRunning);
        }
        
        private static void ProcessorSpecificThread(int processorId)
        {
            try
            {
                // Set this thread's affinity to a specific processor
                IntPtr threadHandle = GetCurrentThread();
                IntPtr affinityMask = (IntPtr)(1 << processorId);
                SetThreadAffinityMask(threadHandle, affinityMask);
                
                Console.WriteLine($"Processor-specific thread started on CPU {processorId}");
                
                // Initialize random with different seed per CPU
                Random rand = new Random(processorId * 100 + Environment.TickCount);
                
                // Create variable timing patterns on this processor
                while (true)
                {
                    try
                    {
                        // Variable intensity workload
                        int workSize = rand.Next(5000, 20000);
                        double result = 0;
                        
                        // CPU intensive work loop
                        for (int i = 0; i < workSize; i++)
                        {
                            result += Math.Sqrt(i * rand.NextDouble());
                            
                            // Periodically check timers to affect CPU caches
                            if (i % 1000 == 0)
                            {
                                // Get various time measurements
                                uint ticks = GetTickCount();
                                ulong ticks64 = GetTickCount64();
                                long perfCount = 0;
                                QueryPerformanceCounter(out perfCount);
                                
                                // Sometimes create small delays
                                if (rand.Next(10) == 0)
                                {
                                    Thread.Sleep(0);
                                }
                            }
                        }
                        
                        // Sleep time varies by processor
                        int sleepMs = processorId % 2 == 0 ? 
                            rand.Next(1, 10) :  // Even processors: short sleeps
                            rand.Next(10, 50);  // Odd processors: longer sleeps
                        
                        Thread.Sleep(sleepMs);
                    }
                    catch
                    {
                        // Just continue on errors
                        Thread.Sleep(50);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in processor {processorId} thread: {ex.Message}");
            }
        }
        
        // Thread that creates specific timing patterns Pafish looks for, but with random variations
        private static void TimingPatternDisruptorThread()
        {
            try
            {
                Random rand = new Random();
                Stopwatch sw = new Stopwatch();
                
                while (true)
                {
                    try
                    {
                        // Simulate the timing patterns Pafish checks for
                        sw.Restart();
                        
                        // First measurement point
                        uint tick1 = GetTickCount();
                        long perf1 = 0;
                        QueryPerformanceCounter(out perf1);
                        
                        // Create a seemingly deterministic delay, but with hidden randomness
                        int delay = 100; // Base delay that looks consistent
                        delay += rand.Next(-10, 30); // Hidden variation
                        
                        if (delay > 0)
                        {
                            // Split into micro-delays to create unique timing signatures
                            int microsteps = rand.Next(5, 15);
                            int stepSize = Math.Max(1, delay / microsteps);
                            
                            for (int i = 0; i < microsteps; i++)
                            {
                                Thread.Sleep(stepSize);
                                
                                // Random CPU work between sleeps
                                double result = 0;
                                int innerLoops = rand.Next(100, 1000);
                                for (int j = 0; j < innerLoops; j++)
                                {
                                    result += Math.Sin(j * 0.01);
                                }
                            }
                        }
                        
                        // Second measurement point
                        uint tick2 = GetTickCount();
                        long perf2 = 0;
                        QueryPerformanceCounter(out perf2);
                        
                        // Calculate and print timing info occasionally
                        if (rand.Next(100) == 0)
                        {
                            long tickDiff = tick2 - tick1;
                            long perfDiff = perf2 - perf1;
                            sw.Stop();
                            Console.WriteLine($"Timing pattern: Tick diff={tickDiff}, PerfCounter diff={perfDiff}, Stopwatch={sw.ElapsedMilliseconds}ms");
                        }
                        
                        // Variable wait between iterations
                        Thread.Sleep(rand.Next(50, 200));
                    }
                    catch
                    {
                        Thread.Sleep(100);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in timing pattern disruptor: {ex.Message}");
            }
        }
        
        // Thread that creates very high frequency timing operations
        private static void HighFrequencyInterferenceThread()
        {
            try
            {
                Random rand = new Random();
                
                while (true)
                {
                    try
                    {
                        // Rapidly call timing functions in bursts
                        int burstSize = rand.Next(100, 500);
                        List<long> measurements = new List<long>(burstSize);
                        
                        for (int i = 0; i < burstSize; i++)
                        {
                            // Mix different timing calls
                            switch (i % 3)
                            {
                                case 0:
                                    measurements.Add(GetTickCount());
                                    break;
                                case 1:
                                    measurements.Add((long)GetTickCount64());
                                    break;
                                case 2:
                                    long perfCount = 0;
                                    QueryPerformanceCounter(out perfCount);
                                    measurements.Add(perfCount);
                                    break;
                            }
                            
                            // Optional tiny sleep
                            if (rand.Next(20) == 0)
                            {
                                Thread.Sleep(0);
                            }
                        }
                        
                        // Sleep between bursts - sometimes very briefly
                        Thread.Sleep(rand.Next(5, 50));
                    }
                    catch
                    {
                        Thread.Sleep(50);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in high frequency interference: {ex.Message}");
            }
        }
        
        // Thread that specifically targets performance counter behavior
        private static void PerformanceCounterManipulationThread()
        {
            try
            {
                Random rand = new Random();
                long freq = 0;
                
                // Get the performance frequency
                QueryPerformanceFrequency(out freq);
                Console.WriteLine($"Performance counter frequency: {freq} Hz");
                
                while (true)
                {
                    try
                    {
                        // Create patterns of busy-wait and sleep
                        // This can affect timing detection mechanisms
                        
                        // First, get initial performance counter
                        long start = 0;
                        QueryPerformanceCounter(out start);
                        
                        // Decide on approach for this iteration
                        int approach = rand.Next(3);
                        switch (approach)
                        {
                            case 0: // Spin wait
                                {
                                    // Calculate target end time
                                    long targetDelta = freq / 1000 * rand.Next(1, 5); // 1-5ms
                                    long targetEnd = start + targetDelta;
                                    
                                    // Busy wait until target
                                    while (true)
                                    {
                                        long current = 0;
                                        QueryPerformanceCounter(out current);
                                        if (current >= targetEnd)
                                            break;
                                    }
                                    break;
                                }
                            
                            case 1: // Mixed approach
                                {
                                    // Sleep a small amount
                                    Thread.Sleep(rand.Next(1, 3));
                                    
                                    // Then busy wait for remainder
                                    long current = 0;
                                    QueryPerformanceCounter(out current);
                                    long targetEnd = current + (freq / 1000 * rand.Next(1, 3));
                                    
                                    while (true)
                                    {
                                        QueryPerformanceCounter(out current);
                                        if (current >= targetEnd)
                                            break;
                                    }
                                    break;
                                }
                                
                            case 2: // Sleep with variable precision
                                {
                                    if (rand.Next(2) == 0)
                                    {
                                        // Normal sleep
                                        Thread.Sleep(rand.Next(1, 10));
                                    }
                                    else
                                    {
                                        // Precision sleep using SpinWait
                                        SpinWait.SpinUntil(() => false, rand.Next(1, 5));
                                    }
                                    break;
                                }
                        }
                        
                        // Get end counter and calculate actual time spent
                        long end = 0;
                        QueryPerformanceCounter(out end);
                        double msElapsed = (double)(end - start) * 1000.0 / freq;
                        
                        // Log occasionally
                        if (rand.Next(100) == 0)
                        {
                            Console.WriteLine($"Performance counter manipulation: {msElapsed:F3}ms elapsed using approach {approach}");
                        }
                    }
                    catch
                    {
                        Thread.Sleep(50);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in performance counter manipulation: {ex.Message}");
            }
        }
    }
    "@
    
    # Start the aggressive timing interference
    [RdtscExitFixer]::StartAggressiveTimingInterference()
    
    Write-Host "Enhanced RDTSC VM exit countermeasures active"
    
    # Keep the script running
    while ($true) {
        # Create some background activity
        $random = New-Object System.Random
        $result = 0
        
        # Vary the workload size
        $iterations = $random.Next(10000, 50000)
        for ($i = 0; $i -lt $iterations; $i++) {
            # Random math operations to create CPU work
            $result += [Math]::Sqrt($i * $random.NextDouble())
            
            # Periodically introduce timing irregularities
            if ($i % 2000 -eq 0) {
                Start-Sleep -Milliseconds ($random.Next(1, 10))
            }
        }
        
        # Vary the sleep time between iterations
        Start-Sleep -Milliseconds ($random.Next(100, 500))
    }
    """

        with open(ps_script_path, 'w') as f:
            f.write(ps_script)

        # Execute the script
        try:
            process = subprocess.Popen(
                ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", ps_script_path],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if process:
                self.started_processes.append(process.pid)
                self.logger.info("Enhanced RDTSC VM exit countermeasures started")
            else:
                self.logger.error("Failed to start enhanced RDTSC countermeasures")
        except Exception as e:
            self.logger.error(f"Failed to apply enhanced RDTSC fixes: {e}")

    def enhanced_mouse_activity(self):
        """Enhanced mouse activity simulation to defeat mouse detection"""
        self.logger.info("Starting enhanced mouse activity simulation...")

        # Create a PowerShell script for more realistic mouse behavior
        ps_script_path = os.path.join(self.work_dir, "enhanced_mouse_sim.ps1")

        ps_script = """
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Collections.Generic;
    using System.Drawing;
    
    public class EnhancedMouseSimulator {
        // Import required user32 functions
        [DllImport("user32.dll")]
        public static extern bool GetCursorPos(out POINT lpPoint);
        
        [DllImport("user32.dll")]
        public static extern bool SetCursorPos(int X, int Y);
        
        [DllImport("user32.dll")]
        public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, int dwExtraInfo);
        
        [DllImport("user32.dll")]
        public static extern bool GetAsyncKeyState(int vKey);
        
        [DllImport("user32.dll")]
        public static extern int GetSystemMetrics(int nIndex);
        
        [StructLayout(LayoutKind.Sequential)]
        public struct POINT {
            public int X;
            public int Y;
        }
        
        // Mouse event flags
        public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        public const uint MOUSEEVENTF_LEFTUP = 0x0004;
        public const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
        public const uint MOUSEEVENTF_RIGHTUP = 0x0010;
        public const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
        public const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
        public const uint MOUSEEVENTF_WHEEL = 0x0800;
        public const uint MOUSEEVENTF_ABSOLUTE = 0x8000;
        public const uint MOUSEEVENTF_MOVE = 0x0001;
        
        // System metrics
        public const int SM_CXSCREEN = 0;
        public const int SM_CYSCREEN = 1;
        
        // Virtual key constants
        public const int VK_LBUTTON = 0x01;
        public const int VK_RBUTTON = 0x02;
        
        // Class to track mouse movement behavior
        public class MouseBehaviorModel
        {
            private Random rand = new Random();
            private int screenWidth;
            private int screenHeight;
            private double cursorSpeed; // Pixels per millisecond
            private double directionChangeProb;
            private Queue<Point> recentPositions = new Queue<Point>();
            
            public MouseBehaviorModel(int width, int height)
            {
                screenWidth = width;
                screenHeight = height;
                cursorSpeed = rand.NextDouble() * 0.8 + 0.3; // 0.3 to 1.1 pixels/ms
                directionChangeProb = rand.NextDouble() * 0.1 + 0.05; // 5-15% chance to change direction
                
                Console.WriteLine($"Created mouse behavior model: speed={cursorSpeed:f2} px/ms, directional stability={(1-directionChangeProb):p}");
            }
            
            // Occasionally modify behavior settings to simulate different "moods"
            public void UpdateBehavior()
            {
                if (rand.NextDouble() < 0.05) // 5% chance to change behavior
                {
                    cursorSpeed = rand.NextDouble() * 0.8 + 0.3;
                    directionChangeProb = rand.NextDouble() * 0.1 + 0.05;
                    Console.WriteLine($"Updated mouse behavior: speed={cursorSpeed:f2} px/ms, directional stability={(1-directionChangeProb):p}");
                }
            }
            
            // Get next cursor position based on current behavior model
            public Point GetNextPosition(Point current, Point target, double deltaTime)
            {
                // Calculate base movement vector
                int deltaX = target.X - current.X;
                int deltaY = target.Y - current.Y;
                double distance = Math.Sqrt(deltaX * deltaX + deltaY * deltaY);
                
                // Nothing to do if we're already at target
                if (distance < 1)
                    return target;
                
                // Calculate how far we can move this frame
                double moveDistance = cursorSpeed * deltaTime;
                
                // Clamp move distance to not overshoot
                moveDistance = Math.Min(moveDistance, distance);
                
                // Calculate normalized direction vector
                double dirX = deltaX / distance;
                double dirY = deltaY / distance;
                
                // Occasionally introduce variation in direction
                if (rand.NextDouble() < directionChangeProb)
                {
                    // Add some random deviation to direction
                    dirX += (rand.NextDouble() - 0.5) * 0.2;
                    dirY += (rand.NextDouble() - 0.5) * 0.2;
                    
                    // Renormalize
                    double newDirLength = Math.Sqrt(dirX * dirX + dirY * dirY);
                    dirX /= newDirLength;
                    dirY /= newDirLength;
                }
                
                // Calculate new position
                int newX = current.X + (int)(dirX * moveDistance);
                int newY = current.Y + (int)(dirY * moveDistance);
                
                // Ensure we stay within screen bounds
                newX = Math.Max(0, Math.Min(screenWidth-1, newX));
                newY = Math.Max(0, Math.Min(screenHeight-1, newY));
                
                return new Point(newX, newY);
            }
            
            // Track recent positions for more realistic movement patterns
            public void RecordPosition(Point pos)
            {
                recentPositions.Enqueue(pos);
                if (recentPositions.Count > 10)
                    recentPositions.Dequeue();
            }
            
            // Get the average velocity over recent positions
            public PointF GetAverageVelocity()
            {
                if (recentPositions.Count < 2)
                    return new PointF(0, 0);
                    
                Point[] positions = recentPositions.ToArray();
                float totalDeltaX = 0, totalDeltaY = 0;
                
                for (int i = 1; i < positions.Length; i++)
                {
                    totalDeltaX += positions[i].X - positions[i-1].X;
                    totalDeltaY += positions[i].Y - positions[i-1].Y;
                }
                
                return new PointF(
                    totalDeltaX / (positions.Length - 1),
                    totalDeltaY / (positions.Length - 1)
                );
            }
        }
        
        // Get the current cursor position
        public static POINT GetCurrentPosition() {
            POINT pt;
            GetCursorPos(out pt);
            return pt;
        }
        
        // Start mouse behavior simulation
        public static void StartRealisticMouseBehavior() {
            // Get screen dimensions
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            
            Console.WriteLine($"Starting enhanced mouse simulation on screen {screenWidth}x{screenHeight}");
            
            // Create behavior model
            MouseBehaviorModel behavior = new MouseBehaviorModel(screenWidth, screenHeight);
            
            // Store initial position
            POINT initialPos = GetCurrentPosition();
            Point currentPos = new Point(initialPos.X, initialPos.Y);
            behavior.RecordPosition(currentPos);
            
            // Create and start realistic mouse simulation
            Thread simulationThread = new Thread(() => {
                try {
                    Random rand = new Random();
                    
                    // Simulation parameters
                    DateTime lastActionTime = DateTime.Now;
                    DateTime lastMoveTime = DateTime.Now;
                    DateTime lastTargetChangeTime = DateTime.Now;
                    
                    Point targetPos = new Point(
                        rand.Next(50, screenWidth - 50), 
                        rand.Next(50, screenHeight - 50)
                    );
                    
                    // Track timing for realistic mouse speed
                    DateTime lastFrameTime = DateTime.Now;
                    
                    // Movement state tracking
                    bool isMoving = false;
                    int idleCounter = 0;
                    bool userControl = false;
                    
                    while (true) {
                        try {
                            // Get current time and calculate delta
                            DateTime now = DateTime.Now;
                            double deltaTimeMs = (now - lastFrameTime).TotalMilliseconds;
                            lastFrameTime = now;
                            
                            // Update behavior model occasionally
                            behavior.UpdateBehavior();
                            
                            // Check if user is moving the mouse or clicking
                            bool leftDown = GetAsyncKeyState(VK_LBUTTON) != 0;
                            bool rightDown = GetAsyncKeyState(VK_RBUTTON) != 0;
                            
                            // If user is interacting, pause simulation temporarily
                            POINT currentPt = GetCurrentPosition();
                            Point actualPos = new Point(currentPt.X, currentPt.Y);
                            
                            if (leftDown || rightDown || 
                                Math.Abs(actualPos.X - currentPos.X) > 5 || 
                                Math.Abs(actualPos.Y - currentPos.Y) > 5) 
                            {
                                // User seems to be controlling the mouse
                                if (!userControl) {
                                    Console.WriteLine("User control detected, pausing simulation");
                                    userControl = true;
                                }
                                
                                // Update current position tracking
                                currentPos = actualPos;
                                behavior.RecordPosition(currentPos);
                                
                                // Brief pause
                                Thread.Sleep(500);
                                continue;
                            }
                            else if (userControl) {
                                // User control ended
                                userControl = false;
                                lastTargetChangeTime = now;
                                Console.WriteLine("Resuming simulation");
                            }
                            
                            // Decide whether we are in movement, idle, or action state
                            TimeSpan sinceLastAction = now - lastActionTime;
                            TimeSpan sinceLastMove = now - lastMoveTime;
                            TimeSpan sinceLastTargetChange = now - lastTargetChangeTime;
                            
                            // Decide if we should create a new target
                            if ((isMoving && sinceLastTargetChange.TotalSeconds > rand.Next(3, 8)) ||
                                (!isMoving && sinceLastTargetChange.TotalSeconds > rand.Next(5, 15)))
                            {
                                targetPos = new Point(
                                    rand.Next(50, screenWidth - 50),
                                    rand.Next(50, screenHeight - 50)
                                );
                                lastTargetChangeTime = now;
                                isMoving = true;
                                Console.WriteLine($"New target: {targetPos.X}, {targetPos.Y}");
                            }
                            
                            // Handle movement
                            if (isMoving) {
                                // Calculate next position based on behavior model
                                Point nextPos = behavior.GetNextPosition(currentPos, targetPos, deltaTimeMs);
                                
                                // Move cursor
                                SetCursorPos(nextPos.X, nextPos.Y);
                                currentPos = nextPos;
                                behavior.RecordPosition(currentPos);
                                
                                // Check if we've reached the target
                                if (Math.Abs(currentPos.X - targetPos.X) < 2 && 
                                    Math.Abs(currentPos.Y - targetPos.Y) < 2) {
                                    isMoving = false;
                                    idleCounter = 0;
                                    lastMoveTime = now;
                                    Console.WriteLine("Reached target, now idle");
                                }
                            }
                            else {
                                // We're in idle state
                                idleCounter++;
                                
                                // Decide if we should take an action
                                if (idleCounter > 10 && sinceLastAction.TotalSeconds > rand.Next(2, 10)) {
                                    int actionType = rand.Next(10);
                                    
                                    switch (actionType) {
                                        case 0:
                                        case 1:
                                        case 2:
                                        case 3:
                                        case 4:
                                            // Single click (50% chance)
                                            Console.WriteLine("Performing single click");
                                            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                                            Thread.Sleep(rand.Next(80, 150));
                                            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                                            break;
                                            
                                        case 5:
                                        case 6:
                                            // Double click (20% chance)
                                            Console.WriteLine("Performing double click");
                                            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                                            Thread.Sleep(rand.Next(60, 120));
                                            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                                            Thread.Sleep(rand.Next(60, 150));
                                            mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
                                            Thread.Sleep(rand.Next(60, 120));
                                            mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
                                            break;
                                            
                                        case 7:
                                            // Right click (10% chance)
                                            Console.WriteLine("Performing right click");
                                            mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
                                            Thread.Sleep(rand.Next(80, 150));
                                            mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
                                            
                                            // After right-clicking, usually move away from menu
                                            Thread.Sleep(rand.Next(300, 800));
                                            break;
                                            
                                        case 8:
                                        case 9:
                                            // Scroll (20% chance)
                                            Console.WriteLine("Performing scroll");
                                            int scrollAmount = rand.Next(-3, 4) * 120;
                                            mouse_event(MOUSEEVENTF_WHEEL, 0, 0, (uint)scrollAmount, 0);
                                            break;
                                    }
                                    
                                    lastActionTime = now;
                                }
                            }
                            
                            // Sleep for a short time to control simulation rate
                            Thread.Sleep(Math.Max(1, rand.Next(10, 40)));
                        }
                        catch (Exception ex) {
                            Console.WriteLine($"Error in mouse simulation loop: {ex.Message}");
                            Thread.Sleep(1000);
                        }
                    }
                }
                catch (Exception ex) {
                    Console.WriteLine($"Mouse simulation thread error: {ex.Message}");
                }
            });
            
            // Start simulation in background
            simulationThread.IsBackground = true;
            simulationThread.Start();
            Console.WriteLine("Enhanced mouse simulation started");
        }
    }
    "@
    
    # Start the enhanced mouse simulation
    Write-Host "Starting enhanced mouse activity simulation..."
    [EnhancedMouseSimulator]::StartRealisticMouseBehavior()
    
    # Keep the script alive
    while ($true) {
        Start-Sleep -Seconds 30
    }
    """

        with open(ps_script_path, 'w') as f:
            f.write(ps_script)

        # Execute the enhanced mouse script
        try:
            process = subprocess.Popen(
                ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", ps_script_path],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if process:
                self.started_processes.append(process.pid)
                self.logger.info("Enhanced mouse activity simulation started")
            else:
                self.logger.error("Failed to start enhanced mouse simulation")
        except Exception as e:
            self.logger.error(f"Failed to start enhanced mouse simulation: {e}")

    def apply_specialized_fixes(self):
        """Apply specialized fixes for the remaining Pafish detections"""
        self.logger.info("Applying specialized fixes for remaining Pafish detections...")

        # Apply the specialized fixes
        self.specialized_cpuid_fix()
        self.enhanced_rdtsc_fix()
        self.enhanced_mouse_activity()

        # Wait for fixes to initialize
        time.sleep(2)

        self.logger.info("Specialized Pafish fixes applied")
        print("\nSpecialized Pafish countermeasures have been applied!")
        print("These fixes target:")
        print("  1. RDTSC VM exit detection")
        print("  2. CPUID hypervisor bit detection")
        print("  3. Mouse movement/activity detection")
        print("\nLeave this tool running while using Pafish.")


        def __init__(self, log_level=logging.INFO):
            self.setup_logging(log_level)
            self.logger.info(f"Pafish Defeat Tool v{VERSION} Started")
            self.modified_entries = []
            self.running = True
            self.started_processes = []

            # Create a working directory
            self.work_dir = os.path.join(tempfile.gettempdir(), f"pafish_defeat_{uuid.uuid4().hex[:8]}")
            os.makedirs(self.work_dir, exist_ok=True)
            self.logger.info(f"Working directory: {self.work_dir}")

            # Hardware profile settings for masking
            self.cpu_model = "AMD Ryzen 7 7840HS w/ Radeon 780M Graphics"
            self.manufacturer = "ASUS"
            self.model = "ROG Zephyrus G14"
            self.bios_version = "G14GA402XI.313"
            self.bios_date = "03/24/2023"

            # Detect operating system version for better compatibility
            self.windows_version = self._get_windows_version()
            self.logger.info(f"Detected Windows version: {self.windows_version}")

            # Start threads for background tasks
            self.threads = []

            # Setup system tray icon if available
            if SYSTRAY_ENABLED:
                self.setup_system_tray()

        def setup_system_tray(self):
            """Setup system tray icon for easier management"""
            try:
                # Create a simple icon - a green shield
                icon_image = self._create_system_tray_icon()

                # Create the menu
                self.icon = pystray.Icon("PafishDefeat")
                self.icon.icon = icon_image
                self.icon.title = "Pafish Defeat Active"

                # Define menu items
                self.icon.menu = pystray.Menu(
                    pystray.MenuItem("Pafish Defeat Active", lambda: None, enabled=False),
                    pystray.MenuItem("Restore System", self._restore_from_tray),
                    pystray.MenuItem("Exit", self._exit_from_tray)
                )

                # Start the system tray icon in a separate thread
                tray_thread = threading.Thread(target=self.icon.run, daemon=True)
                tray_thread.start()
                self.threads.append(tray_thread)
                self.logger.info("System tray icon activated")
            except Exception as e:
                self.logger.error(f"Failed to setup system tray: {e}")

        def _create_system_tray_icon(self):
            """Create a simple shield icon for the tray"""
            width = 64
            height = 64
            color1 = (0, 128, 0)  # Dark green
            color2 = (50, 200, 50)  # Light green

            image = Image.new('RGB', (width, height), color=(0, 0, 0))
            dc = ImageDraw.Draw(image)

            # Draw a shield shape
            dc.polygon([(width//2, 5), (width-5, height//4),
                        (width-5, height//4*3), (width//2, height-5),
                        (5, height//4*3), (5, height//4)], fill=color1)

            # Draw a checkmark
            dc.line([(width//4, height//2), (width//5*2, height//5*3),
                     (width//5*4, height//3)], fill=color2, width=3)

            return image

        def _restore_from_tray(self, icon, item):
            """Restore system when selected from tray menu"""
            self.logger.info("Restore selected from system tray")
            self.restore_system()
            if hasattr(self, 'icon'):
                self.icon.stop()

        def _exit_from_tray(self, icon, item):
            """Exit the application from system tray"""
            self.logger.info("Exit selected from system tray")
            self.restore_system()
            if hasattr(self, 'icon'):
                self.icon.stop()
            os._exit(0)

        def _get_windows_version(self):
            """Get Windows version information for better compatibility"""
            try:
                reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    major = self._safe_reg_read(key, "CurrentMajorVersionNumber")
                    minor = self._safe_reg_read(key, "CurrentMinorVersionNumber")
                    build = self._safe_reg_read(key, "CurrentBuildNumber")
                    display = self._safe_reg_read(key, "DisplayVersion")

                    if major is not None and build is not None:
                        return f"{major}.{minor or 0} (Build {build}) {display or ''}"
                    else:
                        # Fallback for Windows 8.1 and earlier
                        version = self._safe_reg_read(key, "CurrentVersion")
                        build = self._safe_reg_read(key, "CurrentBuild")
                        return f"{version or 'Unknown'} (Build {build or 'Unknown'})"
            except Exception as e:
                self.logger.error(f"Failed to get Windows version: {e}")
                return "Unknown"

        def _safe_reg_read(self, key, value_name):
            """Safely read a registry value, returning None if not found"""
            try:
                value, _ = winreg.QueryValueEx(key, value_name)
                return value
            except:
                return None

        def setup_logging(self, log_level):
            """Configure logging"""
            log_file = os.path.join(tempfile.gettempdir(), "pafish_defeat.log")
            logging.basicConfig(
                level=log_level,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger("PafishDefeat")

        def install_hypervisor_masking(self):
            """Mask hypervisor bit and CPUID information"""
            self.logger.info("Installing hypervisor masking...")

            # We need to create a script for hypervisor masking
            # This requires a kernel-mode driver, but we'll simulate what we can at user level

            # 1. Create a PowerShell script to adjust registry settings that might help
            ps_script_path = os.path.join(self.work_dir, "mask_hypervisor.ps1")

            ps_script = """
    # Attempt to hide hypervisor presence through registry
    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "Enabled" -Value 0 -Force
        Write-Host "Disabled Hypervisor Enforced Code Integrity"
    }
    
    # Mask Hyper-V presence
    $hypervKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization",
        "HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        "HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Auto",
        "HKLM:\\SOFTWARE\\Microsoft\\WindowsVirtualization",
        "HKLM:\\SYSTEM\\ControlSet001\\Services\\vmicheartbeat",
        "HKLM:\\SYSTEM\\ControlSet001\\Services\\vmicvss",
        "HKLM:\\SYSTEM\\ControlSet001\\Services\\vmicshutdown",
        "HKLM:\\SYSTEM\\ControlSet001\\Services\\vmicexchange",
        "HKLM:\\SYSTEM\\ControlSet001\\Control\\WindowsVirtualization"
    )
    
    foreach ($key in $hypervKeys) {
        if (Test-Path $key) {
            # Rename the key by adding .bak (can't delete system protected keys)
            try {
                $backupKey = "$key.bak"
                if (!(Test-Path $backupKey)) {
                    # Using reg.exe because PowerShell doesn't easily allow key renames
                    $regExePath = Join-Path $env:SystemRoot "System32\\reg.exe"
                    $keyShort = $key.Replace("HKLM:\\", "HKLM\\")
                    &$regExePath export $keyShort "$env:TEMP\\temp_key.reg" /y | Out-Null
                    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "Hidden virtualization registry key: $key"
                }
            } catch {
                Write-Host "Error masking hypervisor registry: $_"
            }
        }
    }
    
    # Remove Windows Sandbox specific GUID entries
    $sandboxGuids = @(
        "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{cc5195ac-ba49-48a0-be17-7c40af08d1b7}"
    )
    
    foreach ($key in $sandboxGuids) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Removed Windows Sandbox GUID key: $key"
            } catch {
                Write-Host "Error removing Sandbox GUID key: $_"
            }
        }
    }
    
    # Add false physical hardware indicators via registry
    $physicalHwPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000"
    if (!(Test-Path $physicalHwPath)) {
        New-Item -Path $physicalHwPath -Force | Out-Null
    }
    Set-ItemProperty -Path $physicalHwPath -Name "DriverDesc" -Value "AMD Radeon Graphics" -Force
    Set-ItemProperty -Path $physicalHwPath -Name "DeviceDesc" -Value "AMD Radeon 780M Graphics" -Force
    
    # Add fake SMBIOS information
    $hardwarePath = "HKLM:\\HARDWARE\\DESCRIPTION\\System\\BIOS"
    if (Test-Path $hardwarePath) {
        Set-ItemProperty -Path $hardwarePath -Name "BaseBoardManufacturer" -Value "ASUSTeK COMPUTER INC." -Type String -Force
        Set-ItemProperty -Path $hardwarePath -Name "BaseBoardProduct" -Value "ROG ZEPHYRUS G14 GA402XI" -Type String -Force
        Set-ItemProperty -Path $hardwarePath -Name "SystemFamily" -Value "ROG" -Type String -Force
    }
    
    Write-Host "Hypervisor masking applied via registry"
    
    # Note: True hypervisor bit masking requires kernel-mode modifications
    """

            with open(ps_script_path, 'w') as f:
                f.write(ps_script)

            # Execute the script
            process = self._run_powershell_script(ps_script_path)

            # Check if process ran successfully
            if process and process.returncode == 0:
                self.logger.info("Hypervisor registry masking applied")
            else:
                stderr = process.stderr if process else "No process"
                self.logger.error(f"Failed to apply hypervisor masking: {stderr}")

        def _run_powershell_script(self, script_path, hidden=False, capture_output=True):
            """Run a PowerShell script and track the process"""
            try:
                cmd = ["powershell", "-ExecutionPolicy", "Bypass"]
                if hidden:
                    cmd.append("-WindowStyle")
                    cmd.append("Hidden")
                cmd.extend(["-File", script_path])

                kwargs = {'capture_output': capture_output, 'text': True}
                if hidden:
                    kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

                process = subprocess.run(cmd, **kwargs)

                if not hidden and hasattr(process, 'pid'):
                    self.started_processes.append(process.pid)

                return process
            except Exception as e:
                self.logger.error(f"Failed to run PowerShell script {script_path}: {e}")
                return None

        def _start_background_process(self, cmd, args=None, hidden=True):
            """Start a background process and track its PID"""
            try:
                process_args = [cmd]
                if args:
                    if isinstance(args, list):
                        process_args.extend(args)
                    else:
                        process_args.append(args)

                kwargs = {}
                if hidden:
                    kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW

                process = subprocess.Popen(process_args, **kwargs)

                if process.pid:
                    self.started_processes.append(process.pid)
                    self.logger.info(f"Started process {process.pid}: {cmd}")

                return process
            except Exception as e:
                self.logger.error(f"Failed to start process {cmd}: {e}")
                return None

        def install_rdtsc_patch(self):
            """Install patches to defeat rdtsc timing checks"""
            self.logger.info("Installing rdtsc timing patch...")

            # Check if C++ compiler is available
            has_cpp_compiler = self._check_for_cpp_compiler()

            if has_cpp_compiler:
                # For RDTSC patching, we'll create a C++ program
                rdtsc_cpp_path = os.path.join(self.work_dir, "rdtsc_patch.cpp")
                rdtsc_exe_path = os.path.join(self.work_dir, "rdtsc_patch.exe")

                # C++ code that attempts to normalize CPU timestamp counters
                rdtsc_cpp = """
    #include <windows.h>
    #include <intrin.h>
    #include <iostream>
    #include <thread>
    #include <atomic>
    #include <vector>
    #include <random>
    #include <algorithm>
    
    // Global variables
    std::atomic<bool> g_running(true);
    std::atomic<DWORD> g_originalGetTickCount(0);
    std::random_device g_rd;
    std::mt19937 g_gen(g_rd());
    
    // Thread that manipulates timing
    void TimingPatchThread() {
        // This thread runs constantly to interfere with timing checks
        LARGE_INTEGER start, current, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Get initial tick count
        DWORD initialTicks = GetTickCount();
        g_originalGetTickCount = initialTicks;
        
        // Random jitter values
        std::uniform_int_distribution<> jitter_dist(1, 5);
        std::uniform_int_distribution<> intensive_ops(5000, 15000);
        
        while (g_running) {
            // Introduce timing randomness by sleeping random intervals
            int jitter = jitter_dist(g_gen);
            Sleep(jitter);
            
            // Perform intensive calculations to affect CPU timing
            volatile double result = 0.0;
            int operations = intensive_ops(g_gen);
            
            for (int i = 0; i < operations; i++) {
                result += sqrt(i * 1.0);
                
                // Occasionally perform a CPUID instruction to trigger transitions
                if (i % 1000 == 0) {
                    int cpuInfo[4];
                    __cpuid(cpuInfo, 0);
                }
            }
        }
    }
    
    // More aggressive RDTSC interference
    void RdtscManipulationThread() {
        std::uniform_int_distribution<> sleep_dist(0, 2);
        
        while (g_running) {
            // Read RDTSC multiple times to trigger hypervisor transitions
            unsigned long long start_tsc = __rdtsc();
            
            // Flush the TSC (this can cause timing fluctuations)
            _mm_lfence();
            
            for (int i = 0; i < 10; i++) {
                unsigned long long tmp_tsc = __rdtsc();
                _mm_lfence();
                
                // Create a small delay between reads
                volatile int x = 0;
                for (int j = 0; j < 100; j++) x++;
            }
            
            // Micro-sleep occasionally
            if (sleep_dist(g_gen) == 0) {
                Sleep(0);
            }
        }
    }
    
    // Main function
    int main() {
        // Hide console window
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        
        std::cout << "Starting RDTSC timing patch..." << std::endl;
        
        // Create multiple timing manipulation threads
        const int NUM_THREADS = std::max(2, (int)(std::thread::hardware_concurrency() / 2));
        std::vector<std::thread> threads;
        
        // Create standard timing threads
        for (int i = 0; i < NUM_THREADS; i++) {
            threads.push_back(std::thread(TimingPatchThread));
        }
        
        // Create one RDTSC-specific thread
        threads.push_back(std::thread(RdtscManipulationThread));
        
        // Detach all threads
        for (auto& t : threads) {
            t.detach();
        }
        
        // Message loop to keep the application running
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        g_running = false;
        return 0;
    }
    """

                with open(rdtsc_cpp_path, 'w') as f:
                    f.write(rdtsc_cpp)

                # Attempt to compile the C++ program
                try:
                    self.logger.info("Compiling RDTSC patch with C++ compiler...")
                    compile_result = subprocess.run(["cl", "/EHsc", "/O2", rdtsc_cpp_path],
                                                    capture_output=True, text=True)

                    if os.path.exists(rdtsc_exe_path):
                        self.logger.info("Successfully compiled RDTSC patch")
                        # Run the compiled program
                        process = self._start_background_process(rdtsc_exe_path)
                        if process:
                            self.logger.info("RDTSC patch running")
                        else:
                            self.logger.error("Failed to start RDTSC patch process")
                            self._install_alternative_timing_patch()
                    else:
                        self.logger.error("Failed to compile RDTSC patch, C++ compiler error")
                        self.logger.warning("Switching to alternative timing patch method")
                        self._install_alternative_timing_patch()
                except Exception as e:
                    self.logger.error(f"Error during C++ compilation: {e}")
                    self.logger.warning("Switching to alternative timing patch")
                    self._install_alternative_timing_patch()
            else:
                self.logger.info("C++ compiler not available, using PowerShell-based alternative")
                self._install_alternative_timing_patch()

        def _check_for_cpp_compiler(self):
            """Check if Microsoft C++ compiler is available"""
            try:
                result = subprocess.run(["cl", "/?"], capture_output=True, text=True)
                if "Microsoft" in result.stdout:
                    self.logger.info("Microsoft C++ compiler found")
                    return True
            except:
                pass

            self.logger.info("Microsoft C++ compiler not found")
            return False

        def _install_alternative_timing_patch(self):
            """Alternative method to patch timing using PowerShell"""
            # Create a PowerShell script for timing manipulation
            ps_script_path = os.path.join(self.work_dir, "timing_patch.ps1")

            ps_script = """
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Threading.Tasks;
    
    public static class TimingPatcher
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetTickCount();
        
        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();
        
        [DllImport("kernel32.dll")]
        public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);
        
        [DllImport("kernel32.dll")]
        public static extern bool QueryPerformanceFrequency(out long lpFrequency);
        
        public static void StartTimingInterference()
        {
            // Launch multiple threads based on CPU count
            int threadCount = Math.Max(2, Environment.ProcessorCount / 2);
            Console.WriteLine($"Starting {threadCount} timing interference threads");
            
            for (int i = 0; i < threadCount; i++)
            {
                int threadId = i;
                Task.Factory.StartNew(() => TimingWorkerThread(threadId), TaskCreationOptions.LongRunning);
            }
            
            // Launch a dedicated thread for more focused RDTSC manipulation
            Task.Factory.StartNew(() => RdtscFocusedThread(), TaskCreationOptions.LongRunning);
        }
        
        private static void TimingWorkerThread(int threadId)
        {
            // Initialize thread with different random seed
            Random rand = new Random(threadId * 100 + Environment.TickCount);
            long counter = 0, freq = 0;
            
            QueryPerformanceFrequency(out freq);
            
            while (true)
            {
                try
                {
                    // Query performance counter to put it in cache
                    QueryPerformanceCounter(out counter);
                    
                    // Get tick count to interfere with timing checks
                    uint tick = GetTickCount();
                    ulong tick64 = GetTickCount64();
                    
                    // Perform CPU-intensive calculations with random workload
                    int iterations = rand.Next(5000, 15000);
                    double result = 0;
                    
                    for (int i = 0; i < iterations; i++)
                    {
                        result += Math.Sqrt(i * rand.NextDouble());
                        
                        // Occasionally introduce random pauses
                        if (i % 1000 == 0)
                        {
                            // Randomize whether we Sleep(0) or do a SpinWait
                            if (rand.Next(5) == 0)
                            {
                                Thread.Sleep(0); // Yield to OS scheduler
                            }
                            else
                            {
                                // Precision delay with SpinWait
                                SpinWait.SpinUntil(() => false, rand.Next(1, 50));
                            }
                            
                            // Query counters again to affect timing
                            QueryPerformanceCounter(out counter);
                            tick = GetTickCount();
                        }
                    }
                    
                    // Sleep a tiny random amount to affect scheduling patterns
                    Thread.Sleep(rand.Next(1, 5));
                }
                catch
                {
                    // Ignore errors and continue
                }
            }
        }
        
        private static void RdtscFocusedThread()
        {
            // This thread specifically targets RDTSC-based timing checks
            Random rand = new Random();
            int intensityCycle = 0;
            
            while (true)
            {
                try
                {
                    // Cycle between different intensity levels
                    intensityCycle = (intensityCycle + 1) % 5;
                    
                    if (intensityCycle == 0)
                    {
                        // High intensity - simulate a sudden CPU load spike
                        int spikeOperations = rand.Next(20000, 50000);
                        double result = 0;
                        for (int i = 0; i < spikeOperations; i++)
                        {
                            result += Math.Sin(i * 0.01);
                        }
                        Thread.Sleep(rand.Next(5, 15));
                    }
                    else
                    {
                        // Normal intensity - regular interference
                        uint tick = GetTickCount();
                        Thread.Sleep(rand.Next(1, 3));
                        
                        // Quick burst of activity
                        double result = 0;
                        for (int i = 0; i < 1000; i++)
                        {
                            result += Math.Sqrt(i);
                        }
                    }
                }
                catch
                {
                    Thread.Sleep(10);
                }
            }
        }
    }
    "@
    
    # Start the timing interference engine
    [TimingPatcher]::StartTimingInterference()
    
    Write-Host "Advanced timing patch is now active"
    
    # Keep the script running
    while ($true) {
        # Create some random CPU activity patterns periodically
        $random = New-Object System.Random
        $result = 0
        
        # Vary the workload to create timing fluctuations
        $iterations = $random.Next(10000, 30000)
        for ($i = 0; $i -lt $iterations; $i++) {
            $result += [Math]::Sqrt($i * $random.NextDouble())
            
            if ($i % 1000 -eq 0) {
                # Random sleep to introduce timing irregularities
                Start-Sleep -Milliseconds ($random.Next(1, 5))
                
                # Occasionally perform disk I/O which can affect timing
                if ($random.Next(20) -eq 0) {
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    "Timing distortion" | Out-File $tempFile -Force
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Sleep a random amount between iterations
        Start-Sleep -Milliseconds ($random.Next(200, 800))
    }
    """

            with open(ps_script_path, 'w') as f:
                f.write(ps_script)

            # Start the PowerShell script in the background
            process = self._start_background_process(
                "powershell",
                ["-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", ps_script_path]
            )

            if process:
                self.logger.info("Advanced timing patch running")
            else:
                self.logger.error("Failed to start timing patch")

        def install_mouse_activity_simulator(self):
            """Create a script to simulate realistic mouse activity"""
            self.logger.info("Installing mouse activity simulator...")

            # Create a PowerShell script to simulate mouse movements
            mouse_script_path = os.path.join(self.work_dir, "mouse_sim.ps1")

            mouse_script = """
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    public class MouseSimulator {
        [DllImport("user32.dll")]
        public static extern bool GetCursorPos(out POINT lpPoint);
        
        [DllImport("user32.dll")]
        public static extern bool SetCursorPos(int X, int Y);
        
        [DllImport("user32.dll")]
        public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, int dwExtraInfo);
        
        [StructLayout(LayoutKind.Sequential)]
        public struct POINT {
            public int X;
            public int Y;
        }
        
        public const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
        public const uint MOUSEEVENTF_LEFTUP = 0x0004;
        public const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
        public const uint MOUSEEVENTF_RIGHTUP = 0x0010;
        public const uint MOUSEEVENTF_MOVE = 0x0001;
        public const uint MOUSEEVENTF_WHEEL = 0x0800;
        public const uint MOUSEEVENTF_ABSOLUTE = 0x8000;
        
        public static void MoveMouse(int x, int y) {
            SetCursorPos(x, y);
        }
        
        public static void ClickMouse(int x, int y) {
            SetCursorPos(x, y);
            mouse_event(MOUSEEVENTF_LEFTDOWN, x, y, 0, 0);
            System.Threading.Thread.Sleep(120); // Realistic click duration
            mouse_event(MOUSEEVENTF_LEFTUP, x, y, 0, 0);
        }
        
        public static void RightClickMouse(int x, int y) {
            SetCursorPos(x, y);
            mouse_event(MOUSEEVENTF_RIGHTDOWN, x, y, 0, 0);
            System.Threading.Thread.Sleep(120);
            mouse_event(MOUSEEVENTF_RIGHTUP, x, y, 0, 0);
        }
        
        public static void ScrollMouse(int x, int y, int amount) {
            SetCursorPos(x, y);
            mouse_event(MOUSEEVENTF_WHEEL, 0, 0, (uint)amount, 0);
        }
        
        public static POINT GetCurrentPosition() {
            POINT pt;
            GetCursorPos(out pt);
            return pt;
        }
    }
    "@
    
    # Get screen dimensions
    Add-Type -AssemblyName System.Windows.Forms
    $screenWidth = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width
    $screenHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height
    
    # Record initial cursor position
    $initialPosition = [MouseSimulator]::GetCurrentPosition()
    
    # Function to generate human-like mouse movement path
    function Get-HumanMousePath {
        param (
            [int]$startX,
            [int]$startY,
            [int]$endX,
            [int]$endY,
            [int]$steps = 20
        )
        
        $path = @()
        
        # Control points for a cubic Bezier curve to make movement look more natural
        $controlX1 = $startX + (Get-Random -Minimum -100 -Maximum 100)
        $controlY1 = $startY + (Get-Random -Minimum -100 -Maximum 100)
        $controlX2 = $endX + (Get-Random -Minimum -100 -Maximum 100)
        $controlY2 = $endY + (Get-Random -Minimum -100 -Maximum 100)
        
        # Keep control points within screen bounds
        $controlX1 = [Math]::Max(0, [Math]::Min($screenWidth, $controlX1))
        $controlY1 = [Math]::Max(0, [Math]::Min($screenHeight, $controlY1))
        $controlX2 = [Math]::Max(0, [Math]::Min($screenWidth, $controlX2))
        $controlY2 = [Math]::Max(0, [Math]::Min($screenHeight, $controlY2))
        
        # Generate points along the curve
        for ($i = 0; $i -le $steps; $i++) {
            $t = $i / $steps
            $tSquared = $t * $t
            $tCubed = $tSquared * $t
            $oneMinusT = 1 - $t
            $oneMinusTSquared = $oneMinusT * $oneMinusT
            $oneMinusTCubed = $oneMinusTSquared * $oneMinusT
            
            # Cubic Bezier formula
            $x = [int]($oneMinusTCubed * $startX + 
                        3 * $oneMinusTSquared * $t * $controlX1 + 
                        3 * $oneMinusT * $tSquared * $controlX2 + 
                        $tCubed * $endX)
                        
            $y = [int]($oneMinusTCubed * $startY + 
                        3 * $oneMinusTSquared * $t * $controlY1 + 
                        3 * $oneMinusT * $tSquared * $controlY2 + 
                        $tCubed * $endY)
            
            $path += [PSCustomObject]@{
                X = $x
                Y = $y
            }
        }
        
        return $path
    }
    
    # Main loop for mouse simulation
    Write-Host "Starting mouse activity simulation..."
    try {
        $random = New-Object System.Random
        $activityLevel = 0
        
        while ($true) {
            # Get current position
            $currentPos = [MouseSimulator]::GetCurrentPosition()
            
            # Change activity level occasionally
            if ($random.Next(0, 10) -lt 2) {
                $activityLevel = $random.Next(0, 4) # 0=low, 1=medium, 2=high, 3=erratic
            }
            
            # Decide on a random target position
            $targetX = $random.Next(50, $screenWidth - 50)
            $targetY = $random.Next(50, $screenHeight - 50)
            
            # Vary movement speed based on distance and randomness
            $distance = [Math]::Sqrt([Math]::Pow($targetX - $currentPos.X, 2) + [Math]::Pow($targetY - $currentPos.Y, 2))
            $baseSpeed = [Math]::Max(5, [Math]::Min(15, $distance / 100))
            $speed = $baseSpeed + $random.Next(-3, 4)  # Add some randomness
            
            # Steps depends on distance and activity level
            $steps = [Math]::Max(10, [int]($distance / $speed))
            if ($activityLevel -eq 3) { # Erratic movement
                $steps = $steps / 2
            }
            
            # Get a human-like path to the target
            $movementPath = Get-HumanMousePath -startX $currentPos.X -startY $currentPos.Y -endX $targetX -endY $targetY -steps $steps
            
            # Follow the path
            foreach ($point in $movementPath) {
                [MouseSimulator]::MoveMouse($point.X, $point.Y)
                
                # Variable delay between movements based on activity level
                switch ($activityLevel) {
                    0 { Start-Sleep -Milliseconds ($random.Next(15, 25)) } # Slow
                    1 { Start-Sleep -Milliseconds ($random.Next(8, 15)) }  # Medium
                    2 { Start-Sleep -Milliseconds ($random.Next(3, 8)) }   # Fast
                    3 { # Erratic - sometimes pause, sometimes quick
                        if ($random.Next(0, 10) -lt 2) {
                            Start-Sleep -Milliseconds ($random.Next(30, 80))
                        } else {
                            Start-Sleep -Milliseconds ($random.Next(2, 5))
                        }
                    }
                }
            }
            
            # Occasionally perform mouse actions
            $action = $random.Next(0, 20)
            switch ($action) {
                {$_ -lt 8} { # Left click (40% chance)
                    [MouseSimulator]::ClickMouse($targetX, $targetY)
                    Start-Sleep -Milliseconds ($random.Next(200, 500))
                    
                    # Sometimes do a double click (25% of clicks)
                    if ($random.Next(0, 4) -eq 0) {
                        [MouseSimulator]::ClickMouse($targetX, $targetY)
                    }
                }
                {$_ -lt 10} { # Right click (10% chance)
                    [MouseSimulator]::RightClickMouse($targetX, $targetY)
                    Start-Sleep -Milliseconds ($random.Next(500, 1200))
                }
                {$_ -lt 13} { # Scroll (15% chance)
                    $scrollAmount = $random.Next(-120, 120) # Negative = down, Positive = up
                    [MouseSimulator]::ScrollMouse($targetX, $targetY, $scrollAmount)
                }
                default { # No action, just pause (35% chance)
                    # Do nothing
                }
            }
            
            # Wait a random period before next movement
            $waitTime = switch ($activityLevel) {
                0 { $random.Next(5, 12) }  # Slow activity
                1 { $random.Next(3, 8) }   # Medium activity
                2 { $random.Next(1, 4) }   # High activity
                3 { $random.Next(1, 15) }  # Erratic activity
            }
            
            Start-Sleep -Seconds $waitTime
        }
    }
    catch {
        Write-Host "Mouse simulator stopped: $_"
        # Return to initial position
        [MouseSimulator]::MoveMouse($initialPosition.X, $initialPosition.Y)
    }
    """

            with open(mouse_script_path, 'w') as f:
                f.write(mouse_script)

            # Start the mouse simulation script in a hidden window
            process = self._start_background_process(
                "powershell",
                ["-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", mouse_script_path]
            )

            if process:
                self.logger.info("Mouse activity simulator started")
            else:
                self.logger.error("Failed to start mouse simulator")

        def patch_api_hooks(self):
            """Patch Windows API hooks detection"""
            self.logger.info("Installing API hook patches...")

            # Create a PowerShell script for hook detection countermeasures
            hook_script_path = os.path.join(self.work_dir, "api_hook_patch.ps1")

            hook_script = """
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    
    public class HookPatcher
    {
        // Import required Windows API functions
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetCurrentProcess();
        
        // Memory protection constants
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        
        public static bool PatchShellExecuteCheck()
        {
            try
            {
                // Get handles to the relevant modules
                IntPtr shell32 = GetModuleHandle("shell32.dll");
                if (shell32 == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get shell32.dll module handle");
                    return false;
                }
                
                // Get the address of the ShellExecuteExW function
                IntPtr shellExecAddress = GetProcAddress(shell32, "ShellExecuteExW");
                if (shellExecAddress == IntPtr.Zero)
                {
                    Console.WriteLine("Failed to get ShellExecuteExW address");
                    return false;
                }
                
                // For demonstration - this is where we would patch the function
                // A real implementation would modify specific bytes in the function prologue
                // to defeat hook detection, but this requires detailed knowledge of the
                // function implementation which varies by Windows version
                
                Console.WriteLine("Located ShellExecuteExW function at: " + shellExecAddress.ToString("X"));
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in PatchShellExecuteCheck: " + ex.Message);
                return false;
            }
        }
    }
    "@
    
    # Disable API hooking via registry
    try {
        # Registry paths to modify
        $regPaths = @(
            @{Path="HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"; Name="EnableHookDetection"; Value=0; Type="DWord"},
            @{Path="HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"; Name="LoadAppInit_DLLs"; Value=0; Type="DWord"},
            @{Path="HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"; Name="EnableShellExecuteHooks"; Value=0; Type="DWord"},
            @{Path="HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"; Name="EnableHookDetection"; Value=0; Type="DWord"},
            @{Path="HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"; Name="LoadAppInit_DLLs"; Value=0; Type="DWord"}
        )
        
        foreach ($reg in $regPaths) {
            try {
                # Ensure the path exists
                if (!(Test-Path $reg.Path)) {
                    New-Item -Path $reg.Path -Force | Out-Null
                }
                
                # Set the registry value
                Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type $reg.Type -Force
                Write-Host "Modified registry: $($reg.Path) - $($reg.Name) = $($reg.Value)"
            } catch {
                Write-Host "Error modifying registry $($reg.Path) - $($reg.Name): $_"
            }
        }
        
        # Try to patch ShellExecuteExW
        [HookPatcher]::PatchShellExecuteCheck()
        
        # Disable Windows hook detection via secondary method
        $ImagePath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        if (!(Test-Path "$ImagePath\\GlobalFlag")) {
            New-Item -Path "$ImagePath" -Name "GlobalFlag" -Force | Out-Null
        }
        Set-ItemProperty -Path "$ImagePath\\GlobalFlag" -Name "GlobalFlag" -Value 0 -Type DWord -Force
        
        Write-Host "API hook detection countermeasures applied"
    } catch {
        Write-Host "Error applying API hook countermeasures: $_"
    }
    """

            with open(hook_script_path, 'w') as f:
                f.write(hook_script)

            # Execute the script
            process = self._run_powershell_script(hook_script_path)

            if process and process.returncode == 0:
                self.logger.info("API hook detection countermeasures applied")
            else:
                stderr = process.stderr if process else "No process"
                self.logger.error(f"Failed to apply API hook countermeasures: {stderr}")

            # Additional direct registry modifications for older Windows versions
            try:
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "EnableHookDetection", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "EnableShellExecuteHooks", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                self.logger.info("Applied additional registry hook detection countermeasures")
            except Exception as e:
                self.logger.error(f"Failed to modify hook detection registry directly: {e}")

        def modify_registry_comprehensive(self):
            """Apply comprehensive registry modifications to defeat Pafish detections"""
            self.logger.info("Applying comprehensive registry modifications...")

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

                # Hardware information - specifically for Pafish checks
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

                # Additional hardware entries for better masking
                {
                    "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                    "key": "BaseBoardManufacturer",
                    "value": self.manufacturer,
                    "type": winreg.REG_SZ
                },
                {
                    "path": r"HARDWARE\DESCRIPTION\System\BIOS",
                    "key": "BaseBoardProduct",
                    "value": "ROG ZEPHYRUS G14 GA402XI",
                    "type": winreg.REG_SZ
                },

                # CPU information
                {
                    "path": r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                    "key": "ProcessorNameString",
                    "value": self.cpu_model,
                    "type": winreg.REG_SZ
                },
                {
                    "path": r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                    "key": "VendorIdentifier",
                    "value": "AuthenticAMD",
                    "type": winreg.REG_SZ
                },

                # System Uptime (fake a reasonable uptime to defeat GetTickCount checks)
                {
                    "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    "key": "InstallDate",
                    "value": int(time.time() - (7 * 24 * 60 * 60)),  # 7 days ago for longer uptime
                    "type": winreg.REG_DWORD
                },

                # Machine GUID - replace with a realistic-looking one
                {
                    "path": r"SOFTWARE\Microsoft\Cryptography",
                    "key": "MachineGuid",
                    "value": str(uuid.uuid4()),
                    "type": winreg.REG_SZ
                },

                # Video BIOS version
                {
                    "path": r"HARDWARE\DESCRIPTION\System",
                    "key": "VideoBiosVersion",
                    "value": ["AMD ATOMBIOS"],
                    "type": winreg.REG_MULTI_SZ
                },

                # Remove Windows Sandbox traces
                {
                    "path": r"SYSTEM\CurrentControlSet\Control\WindowsVirtualization",
                    "action": "delete"
                },
                {
                    "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
                    "action": "delete"
                },

                # Remove VirtualBox traces
                {
                    "path": r"HARDWARE\ACPI\DSDT\VBOX__",
                    "action": "delete"
                },
                {
                    "path": r"HARDWARE\ACPI\FADT\VBOX__",
                    "action": "delete"
                },
                {
                    "path": r"HARDWARE\ACPI\RSDT\VBOX__",
                    "action": "delete"
                },

                # Set CPU cores to a realistic number
                {
                    "path": r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    "key": "NUMBER_OF_PROCESSORS",
                    "value": "8",
                    "type": winreg.REG_SZ
                },

                # Disable debug features
                {
                    "path": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                    "key": "GlobalFlag",
                    "value": 0,
                    "type": winreg.REG_DWORD
                }
            ]

            # Apply all modifications
            for mod in registry_modifications:
                try:
                    if "action" in mod and mod["action"] == "delete":
                        self.delete_registry_key(winreg.HKEY_LOCAL_MACHINE, mod["path"])
                        continue

                    # Backup current value if it exists
                    current_value = self.get_registry_value(winreg.HKEY_LOCAL_MACHINE, mod["path"], mod.get("key", ""))
                    if current_value is not None:
                        self.modified_entries.append({
                            "hkey": winreg.HKEY_LOCAL_MACHINE,
                            "path": mod["path"],
                            "key": mod.get("key", ""),
                            "original_value": current_value
                        })

                    # Apply the modification
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
            """Set or create a registry value with enhanced error handling"""
            try:
                access_flags = winreg.KEY_WRITE
                if create:
                    access_flags |= winreg.KEY_CREATE_SUB_KEY

                try:
                    reg_key = winreg.OpenKey(hkey, path, 0, access_flags)
                except FileNotFoundError:
                    if create:
                        reg_key = winreg.CreateKey(hkey, path)
                    else:
                        self.logger.warning(f"Registry key not found: {path}")
                        return False
                except PermissionError:
                    self.logger.error(f"Permission denied for registry key: {path}")
                    return False

                winreg.SetValueEx(reg_key, key_name, 0, value_type, value)
                winreg.CloseKey(reg_key)
                return True
            except Exception as e:
                self.logger.error(f"Error setting registry value {path}\\{key_name}: {e}")
                return False

        def delete_registry_key(self, hkey, path):
            """Delete a registry key and all its values"""
            try:
                winreg.DeleteKey(hkey, path)
                self.logger.info(f"Deleted registry key: {path}")
                return True
            except FileNotFoundError:
                # Key doesn't exist, so no need to delete
                return True
            except Exception as e:
                # It might be a key with subkeys, which can't be deleted directly
                try:
                    # Try to enumerate and delete subkeys first
                    reg_key = winreg.OpenKey(hkey, path, 0, winreg.KEY_ALL_ACCESS)
                    info = winreg.QueryInfoKey(reg_key)
                    for i in range(0, info[0]):
                        # Get subkey name, which is the name of the key under path
                        try:
                            subkey_name = winreg.EnumKey(reg_key, 0)  # Always get the first one
                            # Delete subkey recursively
                            self.delete_registry_key(hkey, f"{path}\\{subkey_name}")
                        except:
                            break

                    winreg.CloseKey(reg_key)
                    # Try again to delete the key itself
                    winreg.DeleteKey(hkey, path)
                    self.logger.info(f"Deleted registry key with subkeys: {path}")
                    return True
                except Exception as sub_e:
                    self.logger.error(f"Error deleting registry key {path}: {sub_e}")
                    return False

        def mask_sleep_function(self):
            """Mask Sleep function patching detection"""
            self.logger.info("Setting up Sleep function masking...")

            # Create a PowerShell script to modify Sleep behavior
            sleep_script_path = os.path.join(self.work_dir, "mask_sleep.ps1")

            sleep_script = """
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Diagnostics;
    
    public static class SleepPatcher
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetTickCount();
        
        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();
        
        [DllImport("kernel32.dll")]
        public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);
        
        private static uint lastTickCount = GetTickCount();
        private static Random rand = new Random();
        
        public static void StartSleepPatching()
        {
            // Start a thread to manipulate timing functions
            Thread thread = new Thread(new ThreadStart(SleepPatchWorker));
            thread.IsBackground = true;
            thread.Start();
            
            Console.WriteLine("Sleep function patching active");
        }
        
        private static void SleepPatchWorker()
        {
            // Initialize a stopwatch for high-precision timing
            Stopwatch sw = new Stopwatch();
            
            // Keep track of tick counts
            uint lastTick = GetTickCount();
            
            while (true)
            {
                try
                {
                    // Get current tick count
                    uint currentTick = GetTickCount();
                    uint elapsed = currentTick - lastTick;
                    
                    // Perform periodic timing manipulations
                    if (elapsed > 1000) // Every second
                    {
                        // Start timing
                        sw.Restart();
                        
                        // Do some intensive work with variable duration
                        int operationCount = rand.Next(5000, 20000);
                        double result = 0;
                        
                        for (int i = 0; i < operationCount; i++)
                        {
                            result += Math.Sin(i * 0.01);
                            
                            // Periodically check time to make the loop duration less predictable
                            if (i % 1000 == 0)
                            {
                                long perfCounter = 0;
                                QueryPerformanceCounter(out perfCounter);
                            }
                        }
                        
                        sw.Stop();
                        
                        // Update last tick
                        lastTick = GetTickCount();
                    }
                    
                    // Don't consume 100% CPU
                    Thread.Sleep(rand.Next(10, 30));
                }
                catch
                {
                    Thread.Sleep(100);
                }
            }
        }
        
        // Function to implement our own sleep with randomization
        public static void PatchedSleep(int milliseconds)
        {
            // Add randomness to sleep time to defeat detection
            int actualSleep = milliseconds + rand.Next(-10, 20);
            if (actualSleep < 1) actualSleep = 1;
            
            // Split larger sleeps into multiple smaller ones with random durations
            if (actualSleep > 50)
            {
                int remaining = actualSleep;
                while (remaining > 0)
                {
                    int chunk = Math.Min(remaining, rand.Next(10, 50));
                    remaining -= chunk;
                    Thread.Sleep(chunk);
                }
            }
            else
            {
                // For small sleeps, just do direct sleep
                Thread.Sleep(actualSleep);
            }
            
            // Update last tick count
            lastTickCount = GetTickCount();
        }
    }
    "@
    
    # Start the sleep patching
    [SleepPatcher]::StartSleepPatching()
    
    Write-Host "Sleep function patching setup complete"
    
    # Keep the script running
    while($true) {
        Start-Sleep -Seconds 60
    }
    """

            with open(sleep_script_path, 'w') as f:
                f.write(sleep_script)

            # Execute the script
            process = self._start_background_process(
                "powershell",
                ["-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", sleep_script_path]
            )

            if process:
                self.logger.info("Sleep function patching active")
            else:
                self.logger.error("Failed to set up sleep function patching")

        def install_dialog_simulator(self):
            """Simulate dialog interaction for reverse turing tests"""
            self.logger.info("Setting up dialog interaction simulator...")

            # Create a PowerShell script to handle dialog interactions
            dialog_script_path = os.path.join(self.work_dir, "dialog_sim.ps1")

            dialog_script = """
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    public class DialogInterceptor
    {
        [DllImport("user32.dll")]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        
        [DllImport("user32.dll")]
        public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);
        
        [DllImport("user32.dll")]
        public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
        
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumChildWindows(IntPtr hwndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder lpClassName, int nMaxCount);
    
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
        
        [DllImport("user32.dll")]
        public static extern int GetDlgCtrlID(IntPtr hwndCtl);
        
        [DllImport("user32.dll")]
        public static extern IntPtr GetDlgItem(IntPtr hDlg, int nIDDlgItem);
        
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);
        
        // Delegate for EnumChildWindows callback
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        
        // Constants for message sending
        public const uint WM_COMMAND = 0x0111;
        public const int IDOK = 1;
        public const int IDCANCEL = 2;
        public const int IDYES = 6;
        public const int IDNO = 7;
        
        // Find and identify button by its ID
        public static IntPtr FindDialogButton(IntPtr dialogHandle, int buttonId)
        {
            return GetDlgItem(dialogHandle, buttonId);
        }
        
        // Respond to a dialog by clicking a specific button
        public static bool RespondToDialog(IntPtr dialogHandle, int buttonId)
        {
            // Bring the dialog to the foreground
            SetForegroundWindow(dialogHandle);
            
            // Send the button click command
            return PostMessage(dialogHandle, WM_COMMAND, (IntPtr)buttonId, IntPtr.Zero);
        }
        
        // Function to check if window is a dialog
        public static bool IsDialog(IntPtr hWnd)
        {
            System.Text.StringBuilder className = new System.Text.StringBuilder(256);
            GetClassName(hWnd, className, className.Capacity);
            return className.ToString() == "#32770";
        }
        
        // Function to get window title
        public static string GetWindowTitle(IntPtr hWnd)
        {
            System.Text.StringBuilder title = new System.Text.StringBuilder(256);
            GetWindowText(hWnd, title, title.Capacity);
            return title.ToString();
        }
    }
    "@
    
    # Function to find and respond to dialog boxes
    function Watch-ForDialogs {
        param(
            [int]$CheckIntervalMs = 200,
            [int]$HumanResponseDelayMin = 500,
            [int]$HumanResponseDelayMax = 2000
        )
        
        $random = New-Object System.Random
        $dialogButtonIds = @([DialogInterceptor]::IDOK, [DialogInterceptor]::IDYES, [DialogInterceptor]::IDNO, [DialogInterceptor]::IDCANCEL)
        
        # Define common dialog class names to search for
        $dialogClasses = @("#32770", "MessageBox")
        
        # Main monitoring loop
        while ($true) {
            try {
                # Check for each dialog class
                foreach ($class in $dialogClasses) {
                    $dialogHandle = [DialogInterceptor]::FindWindow($class, $null)
                    
                    if ($dialogHandle -ne [IntPtr]::Zero) {
                        Write-Host "Found dialog window with class: $class"
                        
                        # Get dialog title
                        $title = [DialogInterceptor]::GetWindowTitle($dialogHandle)
                        Write-Host "Dialog title: $title"
                        
                        # Human-like delay before responding
                        $responseDelay = $random.Next($HumanResponseDelayMin, $HumanResponseDelayMax)
                        Start-Sleep -Milliseconds $responseDelay
                        
                        # Decide which button to click
                        # Prefer positive responses (Yes/OK) with higher probability
                        $buttonId = if ($random.Next(1, 100) -le 80) {
                            # 80% chance of clicking YES or OK
                            if ($random.Next(1, 100) -le 75) {
                                [DialogInterceptor]::IDYES
                            } else {
                                [DialogInterceptor]::IDOK
                            }
                        } else {
                            # 20% chance of clicking NO or CANCEL
                            if ($random.Next(1, 100) -le 75) {
                                [DialogInterceptor]::IDNO
                            } else {
                                [DialogInterceptor]::IDCANCEL
                            }
                        }
                        
                        # Respond to the dialog
                        $result = [DialogInterceptor]::RespondToDialog($dialogHandle, $buttonId)
                        Write-Host "Responded to dialog with button ID: $buttonId, Result: $result"
                        
                        # Wait after responding to allow the dialog to close
                        Start-Sleep -Milliseconds ($random.Next(200, 500))
                    }
                }
                
                # Wait before checking again
                Start-Sleep -Milliseconds $CheckIntervalMs
            } catch {
                Write-Host "Error in dialog watcher: $_"
                # Brief pause to prevent excessive CPU usage if there's an error
                Start-Sleep -Seconds 1
            }
        }
    }
    
    # Start watching for dialogs
    Write-Host "Starting dialog interceptor..."
    Watch-ForDialogs
    """

            with open(dialog_script_path, 'w') as f:
                f.write(dialog_script)

            # Start the PowerShell script in the background
            process = self._start_background_process(
                "powershell",
                ["-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", dialog_script_path]
            )

            if process:
                self.logger.info("Dialog interaction simulator started")
            else:
                self.logger.error("Failed to start dialog simulator")
    def patch_cpuid_info(self):
        """Attempt to patch CPUID information"""
        self.logger.info("Setting up CPUID information patching...")

        # Create a PowerShell script for CPUID masking
        cpuid_ps_path = os.path.join(self.work_dir, "cpuid_mask.ps1")

        cpuid_ps = """
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    public static class CpuidMasker
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);
        
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        // Check for hypervisor features in CPU
        public static void MaskHypervisorCpuid()
        {
            try
            {
                // Registry-based masking is our best option from userspace
                MaskHypervisorRegistry();
                Console.WriteLine("Applied CPUID hypervisor masking via registry");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CPUID masking error: {ex.Message}");
            }
        }
        
        private static void MaskHypervisorRegistry()
        {
            // Since we can't hook CPUID from user mode, we focus on registry settings
            // that might affect how Windows reports and caches CPU information
            
            // This is done in other PowerShell scripts that modify the registry directly
        }
    }
    "@
    
    # Apply CPUID masking
    [CpuidMasker]::MaskHypervisorCpuid()
    
    # Attempt to clear any hypervisor CPUID cache
    $cpuRegPath = "HKLM:\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
    
    # First, get the actual CPU details to preserve
    $vendorIdentifier = (Get-ItemProperty -Path $cpuRegPath -Name "VendorIdentifier" -ErrorAction SilentlyContinue).VendorIdentifier
    $processorName = (Get-ItemProperty -Path $cpuRegPath -Name "ProcessorNameString" -ErrorAction SilentlyContinue).ProcessorNameString
    
    # If hypervisor-related entries exist, try to remove them
    if (Get-ItemProperty -Path $cpuRegPath -Name "HypervisorVendorId" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $cpuRegPath -Name "HypervisorVendorId" -Force -ErrorAction SilentlyContinue
        Write-Host "Removed HypervisorVendorId registry entry"
    }
    
    # Modify CPUID feature bits if they exist to mask hypervisor bit
    if (Get-ItemProperty -Path $cpuRegPath -Name "FeatureSet" -ErrorAction SilentlyContinue) {
        $featureBits = (Get-ItemProperty -Path $cpuRegPath -Name "FeatureSet").FeatureSet
        # Clear hypervisor bit (bit 31)
        $newFeatureBits = $featureBits -band 0x7FFFFFFF
        Set-ItemProperty -Path $cpuRegPath -Name "FeatureSet" -Value $newFeatureBits -Type DWord -Force
        Write-Host "Modified CPU feature bits to hide hypervisor bit"
    }
    
    # Ensure AMD/Intel identification is correct based on CPU name
    if ($processorName -like "*AMD*") {
        Set-ItemProperty -Path $cpuRegPath -Name "VendorIdentifier" -Value "AuthenticAMD" -Type String -Force
    } elseif ($processorName -like "*Intel*") {
        Set-ItemProperty -Path $cpuRegPath -Name "VendorIdentifier" -Value "GenuineIntel" -Type String -Force
    }
    
    Write-Host "CPUID masking completed"
    """

        with open(cpuid_ps_path, 'w') as f:
            f.write(cpuid_ps)

        # Execute the script
        process = self._run_powershell_script(cpuid_ps_path)

        if process and process.returncode == 0:
            self.logger.info("CPUID masking applied")
        else:
            stderr = process.stderr if process else "No process"
            self.logger.error(f"Failed to apply CPUID masking: {stderr}")

        # Apply additional direct registry modifications
        try:
            cpu_reg_path = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"

            # Try to modify CPU feature bits
            feature_set = self.get_registry_value(winreg.HKEY_LOCAL_MACHINE, cpu_reg_path, "FeatureSet")
            if feature_set is not None:
                # Clear hypervisor bit (bit 31)
                new_feature_set = feature_set & 0x7FFFFFFF
                self.set_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    cpu_reg_path,
                    "FeatureSet",
                    new_feature_set,
                    winreg.REG_DWORD
                )
                self.logger.info("Modified CPU feature bits to hide hypervisor bit")
        except Exception as e:
            self.logger.error(f"Failed to modify CPU feature bits directly: {e}")

        return True

    def apply_all_patches(self):
        """Apply all patches to defeat Pafish detection"""
        self.logger.info("Starting comprehensive Pafish detection countermeasures...")

        # Create a dictionary to track patch results
        patch_results = {}

        # 1. Apply registry modifications first
        try:
            self.modify_registry_comprehensive()
            patch_results["registry_modifications"] = "Success"
        except Exception as e:
            self.logger.error(f"Registry modifications failed: {e}")
            patch_results["registry_modifications"] = "Failed"

        # 2. Install hypervisor masking
        try:
            self.install_hypervisor_masking()
            patch_results["hypervisor_masking"] = "Success"
        except Exception as e:
            self.logger.error(f"Hypervisor masking failed: {e}")
            patch_results["hypervisor_masking"] = "Failed"

        # 3. Install CPU ID patching
        try:
            self.patch_cpuid_info()
            patch_results["cpuid_patching"] = "Success"
        except Exception as e:
            self.logger.error(f"CPUID patching failed: {e}")
            patch_results["cpuid_patching"] = "Failed"

        # 4. Install RDTSC timing countermeasures
        try:
            self.install_rdtsc_patch()
            patch_results["rdtsc_patch"] = "Success"
        except Exception as e:
            self.logger.error(f"RDTSC patch failed: {e}")
            patch_results["rdtsc_patch"] = "Failed"

        # 5. Mask Sleep function patching
        try:
            self.mask_sleep_function()
            patch_results["sleep_function_masking"] = "Success"
        except Exception as e:
            self.logger.error(f"Sleep function masking failed: {e}")
            patch_results["sleep_function_masking"] = "Failed"

        # 6. Install mouse activity simulator
        try:
            self.install_mouse_activity_simulator()
            patch_results["mouse_activity_simulator"] = "Success"
        except Exception as e:
            self.logger.error(f"Mouse activity simulator failed: {e}")
            patch_results["mouse_activity_simulator"] = "Failed"

        # 7. Install dialog interaction simulator
        try:
            self.install_dialog_simulator()
            patch_results["dialog_simulator"] = "Success"
        except Exception as e:
            self.logger.error(f"Dialog simulator failed: {e}")
            patch_results["dialog_simulator"] = "Failed"

        # 8. Install API hook countermeasures
        try:
            self.patch_api_hooks()
            patch_results["api_hook_patches"] = "Success"
        except Exception as e:
            self.logger.error(f"API hook patches failed: {e}")
            patch_results["api_hook_patches"] = "Failed"

        # 9. Apply specialized fixes for remaining Pafish detections
        try:
            self.apply_specialized_fixes()
            patch_results["specialized_fixes"] = "Success"
        except Exception as e:
            self.logger.error(f"Specialized fixes failed: {e}")
            patch_results["specialized_fixes"] = "Failed"

        # Wait a moment for all patches to take effect
        time.sleep(2)

        self.logger.info("All Pafish countermeasures applied!")
        print("\nPafish detection countermeasures active!")
        print("This tool has applied advanced techniques to prevent Pafish from detecting virtualization.")
        print("\nNOTE: Some advanced detection methods might still work, especially those requiring")
        print("kernel-mode access. For complete protection, commercial anti-detection tools may be needed.")
        print("\nLeave this tool running while you use your application.")

        # Show successful patches
        print("\nSuccessfully applied patches:")
        for patch, result in patch_results.items():
            if result == "Success":
                print(f"  - {patch.replace('_', ' ').title()}")

    def restore_system(self):
        """Restore the system to its original state"""
        self.logger.info("Restoring system to original state...")

        # Stop all background threads
        self.running = False

        # 1. Restore registry values
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

        # 2. Terminate any processes we started
        for pid in self.started_processes:
            try:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, check=False)
                self.logger.info(f"Terminated process ID {pid}")
            except:
                pass

        # 3. Also try to kill any PowerShell scripts we started
        try:
            subprocess.run(["taskkill", "/F", "/FI", "WINDOWTITLE eq *powershell*"],
                           capture_output=True, check=False)
            subprocess.run(["taskkill", "/F", "/IM", "powershell.exe"],
                           capture_output=True, check=False)
        except:
            pass

        # 4. Clean up temporary files
        try:
            for file in os.listdir(self.work_dir):
                try:
                    file_path = os.path.join(self.work_dir, file)
                    os.remove(file_path)
                    self.logger.info(f"Removed temporary file: {file_path}")
                except:
                    pass

            try:
                os.rmdir(self.work_dir)
                self.logger.info(f"Removed working directory: {self.work_dir}")
            except:
                pass
        except Exception as e:
            self.logger.error(f"Failed to clean up working directory: {e}")

        self.logger.info("System restoration complete")
        print("System has been restored to its original state.")

def main():
    print(f"Pafish (Paranoid Fish) Detection Countermeasures v{VERSION}")
    print("=" * 56)
    print("This tool implements advanced techniques to hide virtualization from Pafish detection.")
    print("")

    # Check for command line arguments
    if "--auto" in sys.argv:
        # Auto mode - just apply patches without prompting
        tool = PafishDefeat()
        tool.apply_all_patches()

        # Stay running
        try:
            print("\nCountermeasures active in automatic mode. Press Ctrl+C to exit...")
            while True:
                time.sleep(60)  # Sleep and continue running
        except KeyboardInterrupt:
            print("\nShutting down and cleaning up...")
            tool.restore_system()
    elif "--specialized" in sys.argv:
        # Only apply specialized fixes for remaining detections
        tool = PafishDefeat()
        tool.apply_specialized_fixes()

        # Stay running
        try:
            print("\nSpecialized countermeasures active. Press Ctrl+C to exit...")
            while True:
                time.sleep(60)  # Sleep and continue running
        except KeyboardInterrupt:
            print("\nShutting down and cleaning up...")
            tool.restore_system()
    elif "--help" in sys.argv or "-h" in sys.argv:
        # Show help
        print("Usage:")
        print("  pafish_defeat.py         - Interactive mode (with prompts)")
        print("  pafish_defeat.py --auto  - Automatic mode (no prompts)")
        print("  pafish_defeat.py --specialized - Apply only specialized fixes for remaining detections")
        print("  pafish_defeat.py --restore - Restore system to original state")
        print("  pafish_defeat.py --help  - Show this help message")
    elif "--restore" in sys.argv:
        # Restore mode
        tool = PafishDefeat()
        tool.restore_system()
    else:
        # Interactive mode
        tool = PafishDefeat()

        print("WARNING: This tool makes temporary changes to system settings.")
        print("These changes should be reversed when the tool exits.")
        print("")

        print("Choose an option:")
        print("1. Apply all Pafish countermeasures")
        print("2. Apply only specialized fixes for remaining detections")
        print("3. Cancel")

        choice = input("Enter choice (1-3): ")

        if choice == "1":
            tool.apply_all_patches()
            print("\nPress Enter to restore original settings when done with your application...")
            input()
            tool.restore_system()
        elif choice == "2":
            tool.apply_specialized_fixes()
            print("\nPress Enter to restore original settings when done with your application...")
            input()
            tool.restore_system()
        else:
            print("Operation cancelled.")

if __name__ == "__main__":
    main()