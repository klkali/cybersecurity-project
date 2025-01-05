from django import forms

class FileUploadForm(forms.Form):
    file = forms.FileField(label="Select File")

class URLSubmitForm(forms.Form):
    url = forms.URLField(label="Enter a URL", widget=forms.URLInput(attrs={
        'placeholder': 'https://example.com',
        'class': 'form-control'
    }))