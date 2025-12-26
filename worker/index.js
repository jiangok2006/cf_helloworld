addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  return new Response('Hello World from worker', {
    headers: { 'Content-Type': 'text/plain' },
  });
}