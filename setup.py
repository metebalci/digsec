# coding: utf-8
from setuptools import setup

# remove CircleCI link because it points to branch, not a tag etc.
def readme():
    lines = []
    with open('README.md') as f:
        while True:
            line = f.readline()
            if len(line) == 0:
                break
            # remove CircleCI
            if line.startswith('[![CircleCI](https'):
                continue
            lines.append(line)
    return ''.join(lines)

setup(long_description=readme())
