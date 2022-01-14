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
  //const char* new_section_name;
  int new_section_size;
  long new_section_vaddress;
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
       printf("Usage: --add <section vaddress> <section size>\n");
       return 1;
      }
      new_section_vaddress = strtol(argv[i + 1], NULL, 16);
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

  if(print_only)
  {
    printf("Entry=0x%lX\n", file_header.e_entry);  
    printf("Sections=%u, Offset=%lX\n", file_header.e_shnum, file_header.e_shoff); 
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
    return 0;
  }
  
  //unsigned end_addr = phdr[last_vaddress_index].p_vaddr + 
  //                    phdr[last_vaddress_index].p_memsz;
                      
  //Modify existing sections  
  //size_t strtab_old_size = shdr_strtab->sh_size;
  //size_t new_strlen = strlen(new_section_name) + 1;
  //shdr_strtab->sh_size += new_strlen;  
  //size_t strtab_size_increase = shdr_strtab->sh_size - strtab_old_size;
  
  long int olen = ilen;
  //olen += strtab_size_increase;
  olen += new_section_size;
  olen += sizeof(Elf64_Shdr); //New section header
  olen += sizeof(Elf64_Phdr) * file_header.e_phnum;
  olen += sizeof(Elf64_Phdr); //New program header
  olen += 8; //TODO figure this out
  uint8_t* obuffer = (uint8_t*)malloc(olen);
  if(obuffer == NULL)
  {
    printf("Unable to malloc %ld bytes for output buffer\n", olen);
    return 1;
  }
  
  Elf64_Shdr new_shdr;
  new_shdr.sh_name = 0;
  new_shdr.sh_type = SHT_PROGBITS;
  new_shdr.sh_flags = SHF_EXECINSTR | SHF_WRITE | SHF_ALLOC;
  new_shdr.sh_addr = new_section_vaddress;
  new_shdr.sh_offset = shdr[file_header.e_shnum - 1].sh_offset +
                       shdr[file_header.e_shnum - 1].sh_size;  
  new_shdr.sh_size = new_section_size;  
  new_shdr.sh_link = 0;
  new_shdr.sh_info = 0;
  new_shdr.sh_addralign = 0x1;
  new_shdr.sh_entsize = sizeof(Elf64_Shdr);
  //This will always come after any existing data
  //new_shdr.sh_offset += strtab_size_increase;
  //new_shdr.sh_offset += sizeof(Elf64_Phdr);
  
  Elf64_Phdr new_phdr;
  new_phdr.p_type = PT_LOAD;
  new_phdr.p_flags = PF_R | PF_W | PF_X;
  new_phdr.p_offset = new_shdr.sh_offset;
  new_phdr.p_vaddr = new_section_vaddress;
  new_phdr.p_paddr = new_phdr.p_vaddr;
  new_phdr.p_filesz = new_phdr.p_memsz;
  new_phdr.p_memsz = new_shdr.sh_size;  
  new_phdr.p_align = 0x1;
  
  file_header.e_shnum += 1;
  //file_header.e_phnum += 1;  
  file_header.e_shoff = new_shdr.sh_size + new_shdr.sh_offset;  
 
  const unsigned old_phdr = file_header.e_phoff;
  //This moves the PHDR entries down below SHDR table
  //When we redirect the phdr, hell ensues.
  ///Comment this out to have things run fine
  file_header.e_phoff = file_header.e_shoff + (file_header.e_shnum * sizeof(Elf64_Shdr));

  //ELF Header
  memcpy(obuffer, &file_header, sizeof(Elf64_Ehdr));
  printf("Elf Header %lX - %lX\n", 0, sizeof(Elf64_Ehdr));
  printf("New PHDR Table = %lX\n", file_header.e_phoff);

  //Program Header Table
  uint8_t* obuffer_ppht = obuffer + file_header.e_phoff;
  uint8_t* obuffer_old = obuffer + old_phdr;
  for(unsigned i = 0; i < file_header.e_phnum; ++i)
  {
   
    Elf64_Phdr uphdr = phdr[i];
    
    //if(uphdr.p_type == PT_PHDR)
    //uphdr.p_offset = (obuffer_ppht - obuffer);
    
    printf("PHDR[%u] %lX - ", i, obuffer_old - obuffer);
    memcpy(obuffer_old, &uphdr, sizeof(Elf64_Phdr));
    obuffer_old += sizeof(Elf64_Phdr);
    printf("%lX\n", obuffer_old - obuffer);
    
    printf("PHDR[%u] %lX - ", i, obuffer_ppht - obuffer);
    memcpy(obuffer_ppht, &uphdr, sizeof(Elf64_Phdr));
    obuffer_ppht += sizeof(Elf64_Phdr);    
    printf("%lX\n", obuffer_ppht - obuffer);
  }

  /*
  memcpy(obuffer_ppht, &new_phdr, sizeof(Elf64_Phdr)); 
  printf("* PHDR[%u] %lX - %lX\n", file_header.e_phnum - 1,
    obuffer_ppht - obuffer,
    (obuffer_ppht + sizeof(Elf64_Phdr)) - obuffer);
    */
  
  //Sections  
  for(unsigned i = 0; i < file_header.e_shnum - 1; ++i)
  {
    if(shdr[i].sh_size == 0) continue;    
    Elf64_Off old_offset = shdr[i].sh_offset;
    Elf64_Off new_offset = shdr[i].sh_offset;// + sizeof(Elf64_Phdr);
    memcpy(obuffer + new_offset, ibuffer + old_offset, shdr[i].sh_size);
    //memcpy(obuffer + shdr[i].sh_offset, ibuffer + shdr[i].sh_offset, shdr[i].sh_size);
    printf("Section[%u] %lX - %lX\n", i, new_offset, new_offset + shdr[i].sh_size);
    shdr[i].sh_offset = new_offset;
  }
  memset(obuffer + new_shdr.sh_offset, 0, new_shdr.sh_size);
  printf("* Section[%u] %lX - %lX\n",
    file_header.e_shnum - 1,
    new_shdr.sh_offset,
    new_shdr.sh_offset + new_shdr.sh_size);
  
  uint8_t* obuffer_psht = obuffer + file_header.e_shoff;
  //Section Header Table  
  for(unsigned i = 0; i < file_header.e_shnum - 1; ++i)
  {
    //shdr[i].sh_offset += sizeof(Elf64_Phdr);
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
  printf("Added Section Offset: %lX, Size: %lX, Address: %lX\n",
    new_shdr.sh_offset, new_shdr.sh_size, new_shdr.sh_addr);
  printf("Added Segment: Offset: %lX, VAddress: %lX, MemSz: %lX\n",
    new_phdr.p_offset, new_phdr.p_vaddr, new_phdr.p_memsz);
    
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
