#include <linux/types.h>
#include <linux/elf-em.h>
#include <elf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <byteswap.h>
#include <stdbool.h>

int main(int argc, const char** argv)
{
  const char* file_name;
  const char* new_section_name;
  int new_section_size;
  bool print_only = false;

  if(argc < 2)
  {
    printf("%s --help to show more information\n", argv[0]);
    return 1;
  }
  if(strcmp(argv[1], "--help") == 0)
  {
    printf("Written by Aleksander Krimsky v1.1\n");
    printf("--print\n");
    printf("--add <section name> <section size>\n");
    return 1;
  }
  if(argc < 3)
  {
    printf("Usage: %s <file> <args>\n", argv[0]);
    return 1;
  }
  file_name = argv[1];
  for(int i = 2; i < argc; ++i)
  {
    if(strcmp(argv[i], "--print") == 0)
    {
      print_only = true;
      goto program;
    }
    if(strcmp(argv[i], "--add") == 0)
    {
      if(i + 2 >= argc)
      {
       printf("Usage: --add <section name> <section size>\n");
       return 1;
      }
      new_section_name = argv[i + 1];
      new_section_size = atoi(argv[i + 2]);
      goto program;
    }
  }
  
  printf("Usage: %s <file> <args>\n", argv[0]);
  return 1;
  
program: ;
  FILE* ihandle = fopen(file_name, "rb");
  if(ihandle == NULL)
  {
    printf("Unable to open: %s\n", file_name);
    return 1;
  }
  long int ilen = 0;
  fseek(ihandle, 0L, SEEK_END);
  ilen = ftell(ihandle);
  fseek(ihandle, 0L, SEEK_SET);
  uint8_t* ibuffer = malloc(ilen);
  if(ibuffer == NULL)
  {
    printf("Unable to malloc %ld bytes for input buffer\n", ilen);
    return 1;
  }
  
  fread(ibuffer, ilen, 1, ihandle);
  fclose(ihandle);
  
  Elf64_Ehdr file_header;
  memcpy(&file_header, ibuffer, sizeof(Elf64_Ehdr));
  uint32_t magic = 0;
  memcpy(&magic, file_header.e_ident, 4);
  magic = bswap_32(magic);
  if(magic != 0x7F454C46) //7FELF
  {
    printf("%s is not an ELF file\n", argv[1]);
    return 1;
  }
  if(sizeof(Elf64_Shdr) != file_header.e_shentsize)
  {
    printf("Shdr size mismatch\n");
    return 1;
  }
  if(sizeof(Elf64_Phdr) != file_header.e_phentsize)
  {
    printf("Phdr size mismatch\n");
    return 1;
  }
  printf("Entry=0x%lX\n", file_header.e_entry);
  
  printf("Sections=%u, Offset=%lX\n", file_header.e_shnum, file_header.e_shoff); 
  Elf64_Phdr* phdr = (Elf64_Phdr*)(ibuffer + file_header.e_phoff);
  Elf64_Shdr* shdr = (Elf64_Shdr*)(ibuffer + file_header.e_shoff);
  Elf64_Shdr* shdr_strtab = &shdr[file_header.e_shstrndx];  
  const char *const string_table = ibuffer + shdr_strtab->sh_offset;

  for(unsigned i = 0; i < file_header.e_shnum; ++i)
  {  
    printf("[%02u] Section Offset=%08lX, Size=%08lX, Addr=%08lX - %08lX, Name=%s\n",
        i,
        shdr[i].sh_offset,
        shdr[i].sh_size,
        shdr[i].sh_addr,
        shdr[i].sh_addr + shdr[i].sh_size,
        string_table + shdr[i].sh_name);
  }
  
  printf("Segments=%u, Offset=%lX\n", file_header.e_phnum, file_header.e_phoff);
  for(unsigned i = 0; i < file_header.e_phnum; ++i)
  {
    printf("[%02u] Segment Offset=%08lX, Size=%08lX, Addr=%08lX - %08lX\n",
      i,
      phdr[i].p_offset,
      phdr[i].p_memsz,
      phdr[i].p_vaddr,
      phdr[i].p_vaddr + phdr[i].p_memsz);
  }
  
  printf("Sizeof Segments + Header = %lX\n", sizeof(Elf64_Ehdr) + file_header.e_phnum * sizeof(Elf64_Phdr));
  
  if(print_only) return 0;

                
                      
  //Modify existing sections  
  //size_t strtab_old_size = shdr_strtab->sh_size;
  //size_t new_strlen = strlen(new_section_name) + 1;
  //shdr_strtab->sh_size += new_strlen;  
  //size_t strtab_size_increase = shdr_strtab->sh_size - strtab_old_size;
  
  
  int last_phdr_index = -1;
  unsigned last_phdr_vaddress = 0;
  for(unsigned i = 0; i < file_header.e_phnum; ++i)
  {
    if(phdr[i].p_type != PT_LOAD) continue;
    unsigned end_vaddress = phdr[i].p_vaddr + phdr[i].p_memsz;    
    if(end_vaddress > last_phdr_vaddress)
    {
     last_phdr_index = i;
     last_phdr_vaddress = end_vaddress;
    }
  }
  
  int shdr_collision_index = -1;
  for(unsigned i = 0; i < file_header.e_shnum; ++i)
  {
    if(shdr[i].sh_addr > last_phdr_vaddress)
    {
     shdr_collision_index = i;
     break;
    }
  }
  
  if(last_phdr_index == -1)
  {
    printf("Unable to find a PT_LOAD PHDR to extend\n");
    return 1;
  }  
  
  if(shdr_collision_index > -1)
  {
    unsigned max_section_size =
      shdr[shdr_collision_index].sh_addr - 
      last_phdr_vaddress;
    if(new_section_size > max_section_size)
    {
      printf("There is a SHDR[%u] that gets loaded past the"
         "last PT_LOAD PHDR[%d] that we wish to extend\n"
         "New Section Size: %d\n",
         shdr_collision_index,
         last_phdr_index,
         max_section_size);
      new_section_size = max_section_size;
    }
  }  
 
  printf("Selected PHDR[%d] to extend\n", last_phdr_index);
  //return 0;

  //file_header.e_phnum += 1;


  unsigned next_shdr_offset = file_header.e_shoff + (file_header.e_shnum + 1) * sizeof(Elf64_Shdr);
  unsigned cave_vaddress = last_phdr_vaddress;
  printf("Next SHDR: %lX\n", next_shdr_offset);
  printf("New Cave VAddress = %lX\n", cave_vaddress);
  
  long int olen = ilen;
  //olen += strtab_size_increase;
  olen += new_section_size;
  olen += sizeof(Elf64_Shdr); //New section header
  olen += 0x8; //TODO figure this out
  uint8_t* obuffer = (uint8_t*)malloc(olen);
  if(obuffer == NULL)
  {
    printf("Unable to malloc %ld bytes for output buffer\n", olen);
    return 1;
  }
  
  Elf64_Shdr new_shdr;
  new_shdr.sh_name = 0;
  //new_shdr.sh_name = strtab_old_size;
  new_shdr.sh_type = SHT_PROGBITS;
  new_shdr.sh_flags = SHF_EXECINSTR | SHF_WRITE | SHF_ALLOC;
  new_shdr.sh_addr = cave_vaddress;
  new_shdr.sh_offset = next_shdr_offset; 
  new_shdr.sh_size = new_section_size;  
  new_shdr.sh_link = 0;
  new_shdr.sh_info = 0;
  new_shdr.sh_addralign = 0x1;
  new_shdr.sh_entsize = sizeof(Elf64_Shdr);
  //This will always come after any existing data
  //new_shdr.sh_offset += strtab_size_increase;

  
  file_header.e_shnum += 1;
  printf("PHOFF: %lX\n", file_header.e_phoff);

  //ELF Header
  memcpy(obuffer, &file_header, sizeof(Elf64_Ehdr));
  printf("Elf Header %lX - %lX\n", 0, sizeof(Elf64_Ehdr));

  //Program Header Table
  uint8_t* obuffer_ppht = obuffer + file_header.e_phoff;
  for(unsigned i = 0; i < file_header.e_phnum; ++i)
  {    
    printf("PHDR[%u] %lX - ", i, obuffer_ppht - obuffer);
    Elf64_Phdr update_phdr = phdr[i];
    if(i == last_phdr_index)
    {
      update_phdr.p_memsz += new_section_size;
      update_phdr.p_filesz = update_phdr.p_memsz;
      update_phdr.p_flags = PF_R | PF_W | PF_X;
    }    

    memcpy(obuffer_ppht, &update_phdr, sizeof(Elf64_Phdr));
    obuffer_ppht += sizeof(Elf64_Phdr);
    printf("%lX\n", obuffer_ppht - obuffer);
  }
  
  //Sections  
  for(unsigned i = 0; i < file_header.e_shnum - 1; ++i)
  {
    if(shdr[i].sh_size == 0) continue;
    memcpy(obuffer + shdr[i].sh_offset, ibuffer + shdr[i].sh_offset, shdr[i].sh_size);
    printf("Section[%u] %lX - %lX\n", i, shdr[i].sh_offset, shdr[i].sh_offset + shdr[i].sh_size);
    /*
    if(i == file_header.e_shstrndx)
    { 
      printf("string table offset= %lX\n", shdr[i].sh_offset);
      printf("string table size= %lX\n", shdr[i].sh_size);
      printf("string table %lX - %lX\n", shdr[i].sh_offset, shdr[i].sh_offset + shdr[i].sh_size);
      printf("memcpy(%lX, %s, %lu)\n", shdr[i].sh_offset + new_shdr.sh_name, new_section_name, new_strlen);
      //memcpy(obuffer + shdr[i].sh_offset  + new_shdr.sh_name, new_section_name, new_strlen);
    }
    */
  }
  //memcpy(obuffer + prgend_byte + sizeof(Elf64_Phdr), ibuffer + prgend_byte, 1);
  memset(obuffer + new_shdr.sh_offset, 0, new_shdr.sh_size);
  printf("* Section[%u] %lX - %lX\n",
    file_header.e_shnum - 1,
    new_shdr.sh_offset,
    new_shdr.sh_offset + new_shdr.sh_size);
  
  uint8_t* obuffer_psht = obuffer + file_header.e_shoff;
  //Section Header Table  
  for(unsigned i = 0; i < file_header.e_shnum - 1; ++i)
  {
    printf("SHDR[%u -> %lX] %lX - ", i, shdr[i].sh_offset, obuffer_psht - obuffer);
    memcpy(obuffer_psht, &shdr[i], sizeof(Elf64_Shdr));
    obuffer_psht += sizeof(Elf64_Shdr);
    printf("%lX\n", obuffer_psht - obuffer);
  }
  memcpy(obuffer_psht, &new_shdr, sizeof(Elf64_Shdr));
    printf("* SHDR[%u] %lX - %lX\n", file_header.e_shnum - 1,
    obuffer_psht - obuffer,
    (obuffer_psht + sizeof(Elf64_Shdr)) - obuffer); 
  
  printf("File size increased from %lX -> %lX\n", ilen, olen);
  printf("Updated Ehdr Phdr Number: %lu\n", file_header.e_phnum);
  printf("Updated Ehdr Shdr Offset: %lX\n", file_header.e_shoff);
  printf("Updated Ehdr Shdr Number: %lu\n", file_header.e_shnum);
  //printf("Increase string table size from %lX -> %lX\n",
  //  strtab_old_size, shdr_strtab->sh_size);
  printf("Added Section: %s, Offset: %lX, Size: %lX, Address: %lX\n",
    new_section_name, new_shdr.sh_offset, new_shdr.sh_size, new_shdr.sh_addr);
  //printf("Added Segment: Offset: %lX, VAddress: %lX, MemSz: %lX\n",
  //  new_phdr.p_offset, new_phdr.p_vaddr, new_phdr.p_memsz);
    
  FILE* ohandle = fopen("out", "wb");
  if(ohandle == NULL)
  {
    printf("Unable to open: %s\n", "out");
    return 1;
  }
  fwrite(obuffer, sizeof(uint8_t), olen, ohandle);
  fclose(ohandle);        
  return 0;
}
