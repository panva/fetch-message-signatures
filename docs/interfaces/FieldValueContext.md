# Interface: FieldValueContext

Context supplied while deriving HTTP message components.

## Contents

- [Properties](#properties)
  - [relatedRequest](#relatedrequest)
  - [trailers](#trailers)

## Properties

### relatedRequest

> `readonly` **relatedRequest**: `boolean`

Whether the value is requested from the related request of a response.

***

### trailers

> `readonly` **trailers**: `boolean`

Whether the value is requested from the trailer section.
