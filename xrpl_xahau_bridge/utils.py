#!/usr/bin/env python
# coding: utf-8

def read_file(file_path: str):
    with open(file_path, 'r') as file:
        return file.read()