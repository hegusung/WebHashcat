from django import template
register = template.Library()

@register.filter
def mult(value, arg):
    "Multiplies the arg and the value"
    return float(value) * float(arg)

@register.filter
def sub(value, arg):
    "Subtracts the arg from the value"
    return float(value) - float(arg)

@register.filter
def div(value, arg):
    "Divides the value by the arg"
    return float(value) / float(arg)
