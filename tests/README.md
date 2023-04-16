## PLUME embedded testsuite

###Requirements:
* Python3, see requirements.txt
* pcscd (Linux PC/SC daemon)

###Running:
* Start pcscd

```
pcscd -a -f -v
```

###Run main.py from virtual environment 
```
python3 -m venv .venv
```

```
source .venv/bin/activate
```

```
python3 main.py
```
