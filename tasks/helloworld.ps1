Param(
  $name
)

if (!($name)) {
  return "Hello World!"
} else {
  return "Hello ${name}"
}
