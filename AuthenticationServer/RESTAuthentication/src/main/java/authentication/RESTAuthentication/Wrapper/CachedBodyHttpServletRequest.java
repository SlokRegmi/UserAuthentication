package authentication.RESTAuthentication.Wrapper;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * An HttpServletRequest wrapper that caches the request body.
 * This allows the request body (InputStream) to be read multiple times.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    /**
     * Constructs a request object wrapping the given request.
     * It reads the entire input stream from the original request and caches it.
     * @param request The request to wrap.
     * @throws IOException if an I/O error occurs.
     */
    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        // Read the original request's input stream and store it in a byte array.
        // This is the one and only time the original stream is read.
        this.cachedBody = request.getInputStream().readAllBytes();
    }

    /**
     * Returns a new ServletInputStream constructed from the cached body.
     * This can be called multiple times.
     */
    @Override
    public ServletInputStream getInputStream() {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.cachedBody);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return byteArrayInputStream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // Not implemented
            }

            @Override
            public int read() {
                // Reads from the cached byte array stream.
                return byteArrayInputStream.read();
            }
        };
    }

    /**
     * Returns a new BufferedReader constructed from the cached body.
     */
    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(this.getInputStream(), StandardCharsets.UTF_8));
    }
}