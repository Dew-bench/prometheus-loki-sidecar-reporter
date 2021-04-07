import subprocess

s = subprocess.run(["perf","stat","--timeout","100","-x",",","sleep","1"], capture_output=True)

print(s)
