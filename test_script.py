from factory import AlgoFactory
import os
algo = AlgoFactory.get_algo("rsa", None)
rc4 = AlgoFactory.get_algo("rc4", None)
os.chdir("./test")

# Create test copies
with open("Bertrand_Meyer1.JPG", "rb") as fd:
    data = fd.read()

with open("Bertrand_Meyer2.JPG", "wb") as fd:
    fd.write(data)

with open("robert.webm", "rb") as fd:
    data = fd.read()

with open("robert2.webm", "wb") as fd:
    fd.write(data)

with open("test.txt", "rb") as fd:
    data = fd.read()

with open("large_text.txt", "wb") as fd:
    fd.write(data)

with open("small_text.txt", "wb") as fd:
    fd.write(bytes(5))
    fd.write(bytes("CHIEF KEEF", "utf-8"))

# algo.encrypt("Bertrand_Meyer2.JPG")
# algo.decrypt("Bertrand_Meyer2.JPG")
#
# algo.encrypt("robert2.webm")
# algo.decrypt("robert2.webm")

# algo.encrypt("test2.txt")
# algo.decrypt("test2.txt")

# rc4.encrypt("Bertrand_Meyer2.JPG")
# rc4.decrypt("Bertrand_Meyer2.JPG")
# rc4.encrypt("robert2.webm")
# rc4.decrypt("robert2.webm")
# rc4.encrypt("test.txt")
# rc4.decrypt("test.txt")
