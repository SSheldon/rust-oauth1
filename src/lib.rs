struct Token<'a> {
    pub key: &'a str,
    pub secret: &'a str,
}

fn authorization<I, K, V>(method: &str, uri: &str, timestamp: &str,
        nonce: &str, consumer: Token, token: Option<Token>, params: I)
        -> String
        where K: AsRef<str>, V: AsRef<str>, I: Iterator<Item=(K, V)> {
    "".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{Token, authorization};

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
            "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b",
            "137131201",
            "7d8f3e4a",
            consumer,
            Some(token),
            params.into_iter(),
        );

        let expected = "OAuth oauth_consumer_key=\"9djdj82h48djs9d2\", \
                        oauth_token=\"kkk9d7dh3k39sjv7\", \
                        oauth_signature_method=\"HMAC-SHA1\", \
                        oauth_timestamp=\"137131201\", \
                        oauth_nonce=\"7d8f3e4a\", \
                        oauth_signature=\"djosJKDKJSD8743243%2Fjdk33klY%3D\"";
        assert_eq!(result, expected);
    }
}
