import textwrap

def wrap_labels(list_of_labels, width=70):
    return [textwrap.fill(text, width) for text in list_of_labels]