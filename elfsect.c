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
    printf("Written by Aleksander Krimsky v1.0\n");
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
  
program:
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
  Elf64_Phdr* phdr = (Elf64_Phdr*)(ibuffer + file_header.e_phoff);
  Elf64_Shdr* shdr = (Elf64_Shdr*)(ibuffer + file_header.e_shoff);
  Elf64_Shdr* shdr_strtab = &shdr[file_header.e_shstrndx];  
  const char *const string_table = ibuffer + shdr_strtab->sh_offset;

  printf("Section Headers: %lu\n", file_header.e_shnum);
  for(unsigned i = 0; i < file_header.e_shnum; ++i)
  {  
    printf("[%02u|%08lx] Section Offset=%08lX, Size=%08lX, Name=%s\n",
        i,
        (uint8_t*)&shdr[i] - ibuffer,
        shdr[i].sh_offset,
        shdr[i].sh_size,
        string_table + shdr[i].sh_name);
  }
  if(print_only) return 0;
  
  //Modify existing sections
  file_header.e_shnum += 1;  
  size_t strtab_old_size = shdr_strtab->sh_size;
  size_t new_strlen = strlen(new_section_name) + 1;
  shdr_strtab->sh_size += new_strlen;
  size_t strtab_size_increase = shdr_strtab->sh_size - strtab_old_size;
  
  //Increase the offset of all subsequent section header tables
  //to account for addition of new string to the string table
  for(unsigned i = file_header.e_shstrndx;
      i < file_header.e_shnum - 2; ++i)
  {
    printf("(%u, %u) Increasing %s offset by %lX\n",
    i, file_header.e_shstrndx,
    string_table + shdr[i].sh_name, strtab_size_increase);
    shdr[i].sh_offset += strtab_size_increase;
  }  
  
  long int olen = ilen;
  olen += strtab_size_increase;
  olen += new_section_size;
  olen += sizeof(Elf64_Shdr);
  uint8_t* obuffer = (uint8_t*)malloc(olen);
  if(obuffer == NULL)
  {
    printf("Unable to malloc %ld bytes for output buffer\n", olen);
    return 1;
  }
  
  Elf64_Shdr new_shdr;
  new_shdr.sh_name = 0;
  new_shdr.sh_type = SHT_PROGBITS;
  new_shdr.sh_flags = SHF_EXECINSTR | SHF_WRITE;
  new_shdr.sh_size = new_section_size;
  new_shdr.sh_offset = shdr[file_header.e_shnum - 2].sh_offset +
                       shdr[file_header.e_shnum - 2].sh_size;
  file_header.e_shoff = new_shdr.sh_size + new_shdr.sh_offset;  
 
  //ELF Header
  memcpy(obuffer, &file_header, sizeof(Elf64_Ehdr));

  //Program Header Table
  if(file_header.e_phoff)
  {
    memcpy(obuffer + sizeof(Elf64_Ehdr),
           ibuffer + sizeof(Elf64_Ehdr),
           sizeof(Elf64_Phdr) * file_header.e_phnum);
  }
  
  //Sections  
  for(unsigned i = 0; i < file_header.e_shnum - 1; ++i)
  {
    memcpy(obuffer + shdr[i].sh_offset, ibuffer + shdr[i].sh_offset, shdr[i].sh_size);
    if(i == file_header.e_shstrndx)
    {
      new_shdr.sh_name = strtab_old_size;
      memcpy(obuffer + shdr[i].sh_offset + new_shdr.sh_name, new_section_name, new_strlen);
    }
  }
  memset(obuffer + new_shdr.sh_offset, 0, new_shdr.sh_size);

  uint8_t* obuffer_psht = obuffer + file_header.e_shoff;
  //Section Header Table  
  for(unsigned i = 0; i < file_header.e_shnum - 1; ++i)
  {
    memcpy(obuffer_psht, &shdr[i], sizeof(Elf64_Shdr));
    obuffer_psht += sizeof(Elf64_Shdr);
  }
  memcpy(obuffer_psht, &new_shdr, sizeof(Elf64_Shdr));
  
  printf("File size increased from %lX -> %lX\n", ilen, olen);
  printf("Updated Ehdr Shdr Offset: %lX\n", file_header.e_shoff);
  printf("Updated Ehdr Shdr Number: %lu\n", file_header.e_shnum);
  printf("Increase string table size from %lX -> %lX\n",
    strtab_old_size, shdr_strtab->sh_size);
  printf("Added Section: %s, Offset: %lX, Size: %lX\n",
    new_section_name, new_shdr.sh_offset, new_shdr.sh_size);
    
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
