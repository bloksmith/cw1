# forms.py

from django import forms
from .models import Contract

class ContractForm(forms.ModelForm):
    class Meta:
        model = Contract
        fields = ['address', 'abi']
from django import forms
from .models import Node

class RegisterMasterNodeForm(forms.ModelForm):
    class Meta:
        model = Node
        fields = ['address', 'public_key']