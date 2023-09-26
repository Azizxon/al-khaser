// al-khaser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

int main(int argc, char* argv[])
{

	API::Init();
	print_os();

	/* Generic sandbox detection */

		loaded_dlls();
		known_file_names();
		known_usernames();
		known_hostnames();
		other_known_sandbox_environment_checks();
		exec_check(&NumberOfProcessors, TEXT("Checking Number of processors in machine "));
		exec_check(&idt_trick, TEXT("Checking Interupt Descriptor Table location "));
		exec_check(&ldt_trick, TEXT("Checking Local Descriptor Table location "));
		exec_check(&gdt_trick, TEXT("Checking Global Descriptor Table location "));
		exec_check(&str_trick, TEXT("Checking Store Task Register "));
		exec_check(&number_cores_wmi, TEXT("Checking Number of cores in machine using WMI "));
		exec_check(&disk_size_wmi, TEXT("Checking hard disk size using WMI "));
		exec_check(&dizk_size_deviceiocontrol, TEXT("Checking hard disk size using DeviceIoControl "));
		exec_check(&setupdi_diskdrive, TEXT("Checking SetupDi_diskdrive "));
		exec_check(&mouse_movement, TEXT("Checking mouse movement "));
		exec_check(&lack_user_input, TEXT("Checking lack of user input "));
		exec_check(&memory_space, TEXT("Checking memory space using GlobalMemoryStatusEx "));
		exec_check(&disk_size_getdiskfreespace, TEXT("Checking disk size using GetDiskFreeSpaceEx "));
		exec_check(&cpuid_is_hypervisor, TEXT("Checking if CPU hypervisor field is set using cpuid(0x1)"));
		exec_check(&cpuid_hypervisor_vendor, TEXT("Checking hypervisor vendor using cpuid(0x40000000)"));
		exec_check(&accelerated_sleep, TEXT("Check if time has been accelerated "));
		exec_check(&VMDriverServices, TEXT("VM Driver Services  "));
		exec_check(&serial_number_bios_wmi, TEXT("Checking SerialNumber from BIOS using WMI "));
		exec_check(&model_computer_system_wmi, TEXT("Checking Model from ComputerSystem using WMI "));
		exec_check(&manufacturer_computer_system_wmi, TEXT("Checking Manufacturer from ComputerSystem using WMI "));
		exec_check(&current_temperature_acpi_wmi, TEXT("Checking Current Temperature using WMI "));
		exec_check(&process_id_processor_wmi, TEXT("Checking ProcessId using WMI "));
		exec_check(&power_capabilities, TEXT("Checking power capabilities "));
		exec_check(&cpu_fan_wmi, TEXT("Checking CPU fan using WMI "));
		exec_check(&query_license_value, TEXT("Checking NtQueryLicenseValue with Kernel-VMDetection-Private "));
		exec_check(&cachememory_wmi, TEXT("Checking Win32_CacheMemory with WMI "));
		exec_check(&physicalmemory_wmi, TEXT("Checking Win32_PhysicalMemory with WMI "));
		exec_check(&memorydevice_wmi, TEXT("Checking Win32_MemoryDevice with WMI "));
		exec_check(&memoryarray_wmi, TEXT("Checking Win32_MemoryArray with WMI "));
		exec_check(&voltageprobe_wmi, TEXT("Checking Win32_VoltageProbe with WMI "));
		exec_check(&portconnector_wmi, TEXT("Checking Win32_PortConnector with WMI "));
		exec_check(&smbiosmemory_wmi, TEXT("Checking Win32_SMBIOSMemory with WMI "));
		exec_check(&perfctrs_thermalzoneinfo_wmi, TEXT("Checking ThermalZoneInfo performance counters with WMI "));
		exec_check(&cim_memory_wmi, TEXT("Checking CIM_Memory with WMI "));
		exec_check(&cim_sensor_wmi, TEXT("Checking CIM_Sensor with WMI "));
		exec_check(&cim_numericsensor_wmi, TEXT("Checking CIM_NumericSensor with WMI "));
		exec_check(&cim_temperaturesensor_wmi, TEXT("Checking CIM_TemperatureSensor with WMI "));
		exec_check(&cim_voltagesensor_wmi, TEXT("Checking CIM_VoltageSensor with WMI "));
		exec_check(&cim_physicalconnector_wmi, TEXT("Checking CIM_PhysicalConnector with WMI "));
		exec_check(&cim_slot_wmi, TEXT("Checking CIM_Slot with WMI "));
		exec_check(&pirated_windows, TEXT("Checking if Windows is Genuine "));
		exec_check(&registry_services_disk_enum, TEXT("Checking Services\\Disk\\Enum entries for VM strings "));
		exec_check(&registry_disk_enum, TEXT("Checking Enum\\IDE and Enum\\SCSI entries for VM strings "));
	

	/* VirtualBox Detection */
		print_category(TEXT("VirtualBox Detection"));
		vbox_reg_key_value();
		exec_check(&vbox_dir, TEXT("Checking VirtualBox Guest Additions directory "));
		vbox_files();
		vbox_reg_keys();
		exec_check(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27 "));
		exec_check(&hybridanalysismacdetect, TEXT("Checking MAC address (Hybrid Analysis) "));
		vbox_devices();
		exec_check(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd "));
		exec_check(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider "));
		vbox_processes();
		exec_check(&vbox_pnpentity_pcideviceid_wmi, TEXT("Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device "));
		exec_check(&vbox_pnpentity_controllers_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBox controller hardware "));
		exec_check(&vbox_pnpentity_vboxname_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBOX names "));
		exec_check(&vbox_bus_wmi, TEXT("Checking Win32_Bus from WMI "));
		exec_check(&vbox_baseboard_wmi, TEXT("Checking Win32_BaseBoard from WMI "));
		exec_check(&vbox_mac_wmi, TEXT("Checking MAC address from WMI "));
		exec_check(&vbox_eventlogfile_wmi, TEXT("Checking NTEventLog from WMI "));
		exec_check(&vbox_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
		exec_check(&vbox_firmware_ACPI, TEXT("Checking ACPI tables  "));
	

	/* VMWare Detection */

		print_category(TEXT("VMWare Detection"));
		vmware_reg_key_value();
		vmware_reg_keys();
		vmware_files();
		vmware_mac();
		exec_check(&vmware_adapter_name, TEXT("Checking VMWare network adapter name "));
		vmware_devices();
		exec_check(&vmware_dir, TEXT("Checking VMWare directory "));
		exec_check(&vmware_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
		exec_check(&vmware_firmware_ACPI, TEXT("Checking ACPI tables  "));
	

	/* Virtual PC Detection */
	
		print_category(TEXT("Virtual PC Detection"));
		virtual_pc_process();
		virtual_pc_reg_keys();
	

	/* QEMU Detection */
	
		print_category(TEXT("QEMU Detection"));
		qemu_reg_key_value();
		qemu_processes();
		qemu_dir();
		exec_check(&qemu_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
		exec_check(&qemu_firmware_ACPI, TEXT("Checking ACPI tables  "));


	/* Xen Detection */

		print_category(TEXT("Xen Detection"));
		xen_process();
		exec_check(&xen_check_mac, TEXT("Checking Mac Address start with 08:16:3E "));


	/* KVM Detection */

		print_category(TEXT("Xen Detection"));
		kvm_files();
		kvm_reg_keys();
		exec_check(&kvm_dir, TEXT("Checking KVM virio directory "));

	/* Wine Detection */

		print_category(TEXT("Wine Detection"));
		exec_check(&wine_exports, TEXT("Checking Wine via dll exports "));
		wine_reg_keys();


	/* Paralles Detection */

		print_category(TEXT("Paralles Detection"));
		parallels_process();
		exec_check(&parallels_check_mac, TEXT("Checking Mac Address start with 00:1C:42 "));



		print_category(TEXT("Hyper-V Detection"));
		exec_check(&check_hyperv_driver_objects, TEXT("Checking for Hyper-V driver objects "));
		exec_check(&check_hyperv_global_objects, TEXT("Checking for Hyper-V global objects "));


	/* Timing Attacks */
		print_category(TEXT("Timing-attacks"));
		UINT delayInSeconds = 15U;
		UINT delayInMillis = delayInSeconds * 1000U;
		printf("\n[*] Delay value is set to %u minutes ...\n", delayInSeconds / 60);

		exec_check(timing_NtDelayexecution, delayInMillis, TEXT("Performing a sleep using NtDelayExecution ..."));
		exec_check(timing_sleep_loop, delayInMillis, TEXT("Performing a sleep() in a loop ..."));
		exec_check(timing_SetTimer, delayInMillis, TEXT("Delaying execution using SetTimer ..."));
		exec_check(timing_timeSetEvent, delayInMillis, TEXT("Delaying execution using timeSetEvent ..."));
		exec_check(timing_WaitForSingleObject, delayInMillis, TEXT("Delaying execution using WaitForSingleObject ..."));
		exec_check(timing_IcmpSendEcho, delayInMillis, TEXT("Delaying execution using IcmpSendEcho ..."));
		exec_check(timing_CreateWaitableTimer, delayInMillis, TEXT("Delaying execution using CreateWaitableTimer ..."));
		exec_check(timing_CreateTimerQueueTimer, delayInMillis, TEXT("Delaying execution using CreateTimerQueueTimer ..."));

		exec_check(&rdtsc_diff_locky, TEXT("Checking RDTSC Locky trick "));
		exec_check(&rdtsc_diff_vmexit, TEXT("Checking RDTSC which force a VM Exit (cpuid) "));

	return 0;
}

