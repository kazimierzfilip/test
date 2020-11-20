from elftools.elf.elffile import ELFFile

with open('bubble.elf', 'rb') as f:

	elffile = ELFFile(f)

	print('  %s sections' % elffile.num_sections())
	section = elffile.get_section_by_name('.text')
	print('  Section name: %s, type: %s' %(section.name, section['sh_type']))