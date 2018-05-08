from setuptools import setup
from codecs import open
from os import path


here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(name='filehash',
      version='0.1.dev3',
      description='Module and command-line tool that wraps around hashlib and zlib to facilitate generating checksums / hashes of files and directories.',
      long_description=long_description,
      long_description_content_type='text/x-rst',
      classifiers=[
            "Development Status :: 3 - Alpha",
            "Environment :: Console",
            "Intended Audience :: Developers",
            "Intended Audience :: End Users/Desktop",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python",
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.6",
            "Topic :: Software Development :: Libraries",
            "Topic :: Utilities",
      ],
      url='https://github.com/leonidessaguisagjr/filehash',
      author='Leonides T. Saguisag Jr.',
      author_email='leonidessaguisagjr@gmail.com',
      license='MIT',
      packages=['filehash'],
      include_package_data=True,
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'chkfilehash = filehash.filehash_cli:main',
          ],
      })
