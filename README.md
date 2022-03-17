# libTO

Trusted Objects' libTO is a library used as an abstraction layer between
Trusted Objects' Secure Element and your software, in order to make its usage
as simple as possible.

## Supported Secure Elements

The following Secure Elements are supported by libTO:

- Hardware Secure Element: AVNET TO136

    Visit [Avnet TO136 presentation page](https://www.avnet.com/wps/portal/silica/products/product-highlights/2016/ot-morpho-trusted-objects-to136)

- Software Secure Element: TO-Protect

    Visit [TO-Protect presentation page](https://www.trusted-objects.com/en-products-22/en-to-protect-22.html)

> **Note:** TO136 hardware Secure Element datasheet is missing in this package,
> because directly delivered with TO136.

## Documentation

The provided documentation are integration manuals, describing how to integrate
in your environment Trusted Objects' library for standard MCU.

Please have a look at the *Documents* folder.
The documentation is available as PDF and HTML.

## Sources

The *Sources* directory contains libTO source code, which  implements the API and
helper functions that provide the functionalities of the Secure Element. It is
used on the client side (i.e. the device).
