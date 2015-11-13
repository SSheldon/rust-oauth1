extern crate url;

use url::percent_encoding::{
    FORM_URLENCODED_ENCODE_SET,
    utf8_percent_encode,
    utf8_percent_encode_to,
};

struct Token<'a> {
    pub key: &'a str,
    pub secret: &'a str,
}

fn encode(s: &str) -> String {
    utf8_percent_encode(s, FORM_URLENCODED_ENCODE_SET)
}

fn encode_to(s: &str, output: &mut String) {
    utf8_percent_encode_to(s, FORM_URLENCODED_ENCODE_SET, output);
}

fn signature_base<'a, I>(method: &str, uri: &str, params: I) -> String
        where I: IntoIterator<Item=(&'a str, &'a str)> {
    // Add the encoded method and URI
    let mut result = String::new();
    encode_to(method, &mut result);
    result.push('&');
    encode_to(uri, &mut result);
    result.push('&');

    // Sort the parameters before adding them
    let mut params: Vec<_> = params.into_iter().collect();
    params.sort();

    let encoded_amp = "%26"; // encode("&")
    let encoded_eq = "%3D"; // encode("=")

    // Add parameters, encoded again
    let mut first = true;
    for (k, v) in params {
        if first {
            first = false;
        } else {
            result.push_str(encoded_amp);
        }

        encode_to(k, &mut result);
        result.push_str(encoded_eq);
        encode_to(v, &mut result);
    }

    result
}

fn authorization<I, K, V>(method: &str, uri: &str, timestamp: &str,
        nonce: &str, consumer: Token, token: Option<Token>, params: I)
        -> String
        where K: AsRef<str>, V: AsRef<str>, I: IntoIterator<Item=(K, V)> {
    // Collect and encode the oauth params
    let mut oauth_params = vec![
        ("oauth_consumer_key", encode(consumer.key)),
        ("oauth_signature_method", "HMAC-SHA1".to_owned()),
        ("oauth_timestamp", encode(timestamp)),
        ("oauth_nonce", encode(nonce)),
    ];
    if let Some(token) = token {
        oauth_params.insert(1, ("oauth_token", encode(token.key)));
    }

    // Collect and encode the extra params
    let extra_params: Vec<_> = params.into_iter().map(|(k, v)| {
        (encode(k.as_ref()), encode(v.as_ref()))
    }).collect();

    // Combine these params into the signature base
    let base = {
        let oauth_params = oauth_params.iter().map(|&(k, ref v)| (k, &**v));
        let extra_params = extra_params.iter().map(|&(ref k, ref v)| (&**k, &**v));
        signature_base(method, uri, oauth_params.chain(extra_params))
    };

    // Generate the signature from the base
    let signature = String::new();
    oauth_params.push(("oauth_signature", encode(&signature)));

    // Combine everything into the authorization
    let mut auth = "OAuth ".to_owned();
    let mut first = false;
    for (k, v) in oauth_params {
        if first {
            first = false;
        } else {
            auth.push_str(", ");
        }

        auth.push_str(k);
        auth.push_str("=\"");
        auth.push_str(&v);
        auth.push('"');
    }

    auth
}

#[cfg(test)]
mod tests {
    use super::{Token, authorization, signature_base};

    #[test]
    fn test_signature_base() {
        let params = vec![
            ("b5", "%3D%253D"),
            ("a3", "a"),
            ("c%40", ""),
            ("a2", "r%20b"),
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_nonce", "7d8f3e4a"),
            ("c2", ""),
            ("a3", "2%20q"),
        ];

        let result = signature_base(
            "POST",
            "http://example.com/request",
            params,
        );

        let expected = "\
            POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q\
            %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_\
            key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m\
            ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk\
            9d7dh3k39sjv7";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_authorization() {
        let consumer = Token { key: "9djdj82h48djs9d2", secret: "j49sk3j29djd" };
        let token = Token { key: "kkk9d7dh3k39sjv7", secret: "dh893hdasih9" };

        let params = vec![
            ("b5", "=%3D"),
            ("a3", "a"),
            ("c@", ""),
            ("a2", "r b"),
            ("c2", ""),
            ("a3", "2 q"),
        ];

        let result = authorization(
            "POST",
            "http://example.com/request",
            "137131201",
            "7d8f3e4a",
            consumer,
            Some(token),
            params,
        );

        let expected = "\
            OAuth oauth_consumer_key=\"9djdj82h48djs9d2\", \
            oauth_token=\"kkk9d7dh3k39sjv7\", \
            oauth_signature_method=\"HMAC-SHA1\", \
            oauth_timestamp=\"137131201\", \
            oauth_nonce=\"7d8f3e4a\", \
            oauth_signature=\"djosJKDKJSD8743243%2Fjdk33klY%3D\"";
        assert_eq!(result, expected);
    }
}
