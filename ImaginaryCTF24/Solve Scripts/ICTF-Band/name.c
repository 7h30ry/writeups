int name()
{
  int result; // eax
  char ptr[52]; // [rsp+0h] [rbp-90h] BYREF
  int v2; // [rsp+34h] [rbp-5Ch] BYREF
  char v3; // [rsp+3Ah] [rbp-56h] BYREF
  char v4; // [rsp+3Bh] [rbp-55h] BYREF
  int count; // [rsp+3Ch] [rbp-54h] BYREF
  char title[52]; // [rsp+40h] [rbp-50h] BYREF
  int slot; // [rsp+74h] [rbp-1Ch] BYREF
  char genre[8]; // [rsp+78h] [rbp-18h] BYREF
  void *v9; // [rsp+80h] [rbp-10h]
  int v10; // [rsp+88h] [rbp-8h]
  int v11; // [rsp+8Ch] [rbp-4h]

  pretty_print_1();
  v11 = 1;
  if ( is_full == 5 )
  {
    printf("\x1B[1;31m");
    printf(">> ");
    printf("\x1B[0m");
    return puts("Slot is full.");
  }
  else
  {
    puts("Hello there, give me your best idea for a song-name!");
    puts("Before that, please choose at which slot you want to add your preferences.");
    printf("Slot [1-5]: ");
    __isoc99_scanf("%1d", &slot);
    getchar();
    if ( slot <= 5 && slot > 0
      || (puts("Only slot 1 - 5 available."),
          puts("Anyway, how many ictf album you have?"),
          printf("Album Count: "),
          __isoc99_scanf("%99d", &count),
          getchar(),
          count > 0) )
    {
      printf("Let's start by choosing the genre [jazz | pop | rock]: ");
      fgets(genre, 8, stdin);
      printf("Now tell me the song title: ");
      fgets(title, 50, stdin);
      puts(byte_3080);
      printf("\x1B[1;33m");
      printf("[GENRE]: %s\n", genre);
      printf("[TITLE]: %s\n", title);
      printf("\x1B[0m");
      puts(byte_3080);
      puts("I like it! Let's make it a hit!");
      v10 = atoi(title);
      v9 = malloc(v10);
      if ( v9 )
      {
        if ( qword_50A0[slot] )
        {
          printf("\x1B[1;33m");
          puts("[+] Machine Temp is high..");
          printf("\x1B[0;31m");
          puts("[#] Terminating Program.");
          printf("\x1B[0m");
          putchar(46);
          sleep(1u);
          putchar(46);
          sleep(1u);
          putchar(46);
          sleep(1u);
          exit(0);
        }
        qword_50A0[slot] = v9;
        dword_5120[slot] = v10;
      }
      printf("\x1B[1;33m");
      puts("[+] Data saved!");
      printf("\x1B[0m");
      puts(byte_3080);
      puts(byte_3080);
      is_full += v11;
      result = is_full;
      if ( is_full == 5 )
      {
        printf("\x1B[1;31m");
        printf(">> ");
        printf("\x1B[0m");
        return puts("Slot is now full.");
      }
    }
    else
    {
      printf("Would you like to buy one or maybe more? [y/n]: ");
      __isoc99_scanf("%c", &v4);
      if ( v4 == 121 )
      {
        printf("The album should be pre-ordered. Tell us how many you want, we will contact you soon: ");
        __isoc99_scanf("%d", &v2);
        getchar();
        printf("Tell us your e-mail: ");
        fread(ptr, 1uLL, v2, stdin);
        puts(byte_3080);
        printf("\x1B[1;33m");
        puts("[YOUR DATA] Please validate before continuing: ");
        printf("\x1B[0m");
        puts(ptr);
        puts(byte_3080);
        printf("It's verified [y/n]: ");
        __isoc99_scanf("%c", &v3);
        getchar();
        if ( v3 != 121 )
        {
          printf("\x1B[1;33m");
          puts("[+] Machine Temp is high..");
          printf("\x1B[0;31m");
          puts("[#] Terminating Program.");
          printf("\x1B[0m");
          putchar(46);
          sleep(1u);
          putchar(46);
          sleep(1u);
          putchar(46);
          sleep(1u);
          exit(0);
        }
        printf("\x1B[1;35m");
        puts("[@] Thank you for your order, we will contact you soon.");
        return printf("\x1B[0m");
      }
      else
      {
        if ( v4 != 110 )
        {
          printf("\x1B[1;33m");
          puts("[+] Machine Temp is high..");
          printf("\x1B[0;31m");
          puts("[#] Terminating Program.");
          printf("\x1B[0m");
          putchar(46);
          sleep(1u);
          putchar(46);
          sleep(1u);
          putchar(46);
          sleep(1u);
          exit(0);
        }
        return puts("Alright then!");
      }
    }
  }
  return result;
}
