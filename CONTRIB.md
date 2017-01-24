# Style guidelines 

## General

This file is about how all python developers agree on coding guidelines. There is nothing special,
but here its written down. They are based on open stacks python guidelines which are based on googles
python guidelines. To achieve this, we are going to use the hacking lib - in combination with tox.
Read about the details following the links above, or just correct tox's style errors and be fine.
This will be provided within our git repo, so that there will a short setup and then test running
is done with "tox" in the repos root path

## Comments

* `TODO(Name)` is a note to yourself, something that should be done before merging your feature
* `FIXME(Name)` is a note to the team, meaning "this is something wrong, but it works." 
   Explain how it should be fixed.
* `XXX(Name)` is a note to the reader to mark something dirty, or a bad practice. It basically means 
  "it would be great if this was fixed/cleanup, but I don't see how"
* `BBB(Name)` is something dirty, boiler plate left over just for backward compatibility

## Docstrings

Docstrings should be [PEP257](https://www.python.org/dev/peps/pep-0257/) compliant. 
They should follow the Google Style Docstrings so that they can be parsed by the 
[napoleon sphinx extension](http://sphinxcontrib-napoleon.readthedocs.io/en/latest/).
This makes docstrings way more readable than the traditional markup.

### Most common rules

Here is a list of the most common rules - or the rules that are discussed the most:

* Indents are 4 spaces, no tabs
* Line length 100 (this is different to above linked guidelines)
* Put a new line at the end of each file
* Use `'single_quote'` for things that should be used like symbols (like dictionary keys) 
  because they're lighter for the eyes
* Use `"double quote"` for string containing english and might be displayed to the end user. 
  (because english can contain apostrophes like "Denny's").
* Don't mutate `dict`s from outside a function. Always mutate the `dict on your stack.

  Don't do:
  ```python
  def mutate_dict(dictionnary):
      dictionary.update(key='value')
  ```

  Do:
  ```python
  def add_key(dictionnary):
      dictionnary = dictionnary.copy()
      dictionnary.update(key='value')
      return dictionary
  ```

  Because the calling function will do: `d = add_key(d)`, which indicates that the value of d has been mutated.
  You can copy paste once, even though avoid to do that. But *never* copy paste twice.

* Module constants should be in `ALL_CAPS`

* If wrapping is needed in a call: the next line is ONE indent more then the previous, not more! 
  Additionally it should be one line per argument.

  ```python
  # MAYBE!
  foobar_function_name(
      arg1, arg2, arg3)
 
  # MAYBE!
  foobar_function_name(arg1, arg2, arg3,
                       arg4, arg5)
 
  # MAYBE:
  foobar_function_name(
      arg1,
      arg2,
      arg3,
  )
  
  # NO!
  foobar_function_name(arg1,
                       arg2,
                       arg3,
                       arg4,
                       arg5)
  ```

* When *defining* a function, use this:

  ```python
  # YES!
  def foobar_function_name(arg1, arg2, arg3,
                           arg4, arg5)
 
  # NO!:
  def foobar_function_name(
      arg1,
      arg2,
      arg3,
  )
  
  # NO!
  def foobar_function_name(arg1,
                           arg2,
                           arg3,
                           arg4,
                           arg5)
  ```    
                     
* Don't instantiate exception with no arguments, just raise them:

  ```python
  # NO
  raise Exception()
  
  # Yes
  raise Exception
  raise Exception(arg)
  ``` 

* Always leave a trailing comma in order have better diffs:

  ```python
  # NO
  a = {
      'foo': 'bar',
      'bar': 'baz'
  }
  a = foo(
      bar=1,
      baz=2
  )
 
  # Yes
  a = {
      'foo': 'bar',
      'bar': 'baz',
  }
  a = foo(
      bar=1,
      baz=2,
  )
``` 
