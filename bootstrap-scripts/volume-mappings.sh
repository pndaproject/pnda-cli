#!/usr/bin/env python
import subprocess
import sys
import os.path

infile = sys.argv[1]
outfile = sys.argv[2]

if not os.path.isfile(infile):
    print 'No volume mapping file found at: %s. Nothing to do.' % infile
    sys.exit(0)

# Load the list of volumes that are being requested
print 'loading requested volumes from %s' % infile

requested_volumes = []
with open(infile) as requested_volumes_file:
    for line in requested_volumes_file:
        line = line.strip()
        if not line.startswith('#'):
            requested_volumes.append(line.split(' '))

print '\nrequested volumes:'
print requested_volumes
requested_volumes_count = len(requested_volumes)

# Find out what volumes are available
out = subprocess.check_output(['lsblk', '-brn', '-o', 'NAME,SIZE,MOUNTPOINT'])
available_volumes = []
for line in out.splitlines():
    fields = line.split(' ')
    if len(fields) > 0:
      fields[0] = "/dev/%s" % fields[0]
      available_volumes.append(fields)

# Sort by size and name
available_volumes.sort(key=lambda x: (-int(x[1]), x[2]))
print '\navailable volumes:'
print available_volumes

print '\nwriting volume mappings to %s' % outfile
mappings_count = 0
with open(outfile, 'w') as volume_mappings_file:
    # First copy any lines across that already specify the device to use
    all_volume_devices = [volume[0] for volume in available_volumes]
    to_remove = []
    for requested_volume in requested_volumes:
        if len(requested_volume) > 2:
            volume_mappings_file.write(' '.join(requested_volume) + '\n')
            mappings_count += 1
            available_volumes = [item for item in available_volumes if item[0] != requested_volume[0]]
            to_remove.append(requested_volume[0])
            if requested_volume[0][-1].isdigit():
                parent = ''.join([c for c in requested_volume[0] if not c.isdigit()])
                available_volumes = [item for item in available_volumes if item[0] != parent]
    requested_volumes = [item for item in requested_volumes if item[0] not in to_remove]

    # Assign out the remainder in descending size order
    i = 0
    for available_volume in available_volumes:
        if i >= len(requested_volumes):
            break
        requested_volume = requested_volumes[i]
        if (available_volume[0][-1].isdigit() or '%s%s' % (available_volume[0], 1) not in all_volume_devices) and available_volume[2] != '/':
            available_volume = [available_volume[0]]
            available_volume.extend(requested_volume)
            volume_mappings_file.write(' '.join(available_volume) + '\n')
            mappings_count += 1
            i += 1

# Check that each requested volume has a line in the mappings file
if mappings_count != requested_volumes_count:
    print 'ERROR: %s volumes requested but only managed to assign volumes for %s of them' % (requested_volumes_count, mappings_count)
    sys.exit(-1)