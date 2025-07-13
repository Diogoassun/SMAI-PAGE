function BadRequest (message) {
    this.name = 'BadRequest';
    this.message = message || this.name;
    this.stauts = 400; 
}

function Unauthorized (message) {
    this.name = 'Unathorized';
    this.message = message || this.name;
    this.stauts = 401; 
}

BadRequest.prototype = new Error();
Unauthorized.prototype = new Error();

export {
    BadRequest,
    Unauthorized
} 